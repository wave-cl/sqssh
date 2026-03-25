use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use ed25519_dalek::VerifyingKey;
use sqssh_core::auth::{AuthMode, AuthorizedKeys};
use sqssh_core::config::ServerConfig;
use sqssh_core::keys;
use sqssh_core::persist::PersistedSession;
use sqssh_core::protocol::{self, CtlRequest, CtlResponse};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{watch, Mutex, RwLock};
use tokio::task::JoinSet;
use tracing::Instrument;

mod file_handler;
mod pty_handler;
mod sftp_handler;

/// Result of accepting a stream from a QUIC connection.
enum AcceptResult {
    /// Unidirectional stream (raw file upload).
    Uni(quinn::RecvStream),
    /// Raw shell data stream.
    RawShell(quinn::SendStream, quinn::RecvStream, protocol::RawShellHeader),
    /// Raw shell control stream.
    ShellControl,
    /// Raw SFTP session.
    RawSftp(quinn::SendStream, quinn::RecvStream),
    /// Raw exec request.
    RawExec(quinn::SendStream, quinn::RecvStream, String),
    /// Raw download request.
    RawDownloadRequest(quinn::SendStream, quinn::RecvStream, String, u32),
}

#[derive(Parser)]
#[command(name = "sqsshd", about = "sqssh server daemon")]
struct Cli {
    /// Listen address
    #[arg(short = 'l', long)]
    listen: Option<String>,

    /// Listen port (UDP)
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Host key file
    #[arg(short = 'k', long = "host-key")]
    host_key: Option<PathBuf>,

    /// Config file
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Auth mode override
    #[arg(long = "auth-mode")]
    auth_mode: Option<String>,

    /// Disable connection migration
    #[arg(long = "no-migration")]
    no_migration: bool,

    /// Show the server's public key and exit
    #[arg(long = "show-pubkey")]
    show_pubkey: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long = "log-level", default_value = "info")]
    log_level: String,

    /// Log to file instead of stderr
    #[arg(long = "log-file")]
    log_file: Option<PathBuf>,

    /// Output logs as JSON
    #[arg(long = "log-json")]
    log_json: bool,
}

/// Shared server state passed to connection handlers.
/// An active PTY session that can be persisted.
struct ActivePtySession {
    info: PersistedSession,
    master_fd: RawFd,
}

struct ServerState {
    authorized_keys: RwLock<AuthorizedKeys>,
    auth_mode: AuthMode,
    ak_relative: String,
    listener: squic::ServerListener,
    allow_users: Vec<String>,
    deny_users: Vec<String>,
    print_motd: bool,
    print_last_log: bool,
    banner: Option<PathBuf>,
    max_auth_tries: usize,
    max_sessions: usize,
    active_sessions: std::sync::atomic::AtomicUsize,
    /// Active PTY sessions indexed by a unique session ID.
    pty_sessions: Mutex<HashMap<u64, ActivePtySession>>,
    /// Next session ID counter.
    next_session_id: std::sync::atomic::AtomicU64,
    /// Recovered sessions from sqssh-persist, waiting for clients to reconnect.
    /// Keyed by (pubkey, username).
    pending_sessions: Mutex<HashMap<([u8; 32], String), (RawFd, PersistedSession)>>,
}

/// Convert an Ed25519 pubkey to X25519 bytes for the squic whitelist.
fn ed25519_to_x25519(ed_pub: &[u8; 32]) -> Option<[u8; 32]> {
    squic::crypto::ed25519_public_to_x25519(ed_pub)
        .ok()
        .map(|xpub| xpub.to_bytes())
}

fn init_logging(cli: &Cli) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_new(&cli.log_level)
        .unwrap_or_else(|_| EnvFilter::new("info"));

    if cli.log_json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .json()
            .init();
    } else if let Some(ref log_file) = cli.log_file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .expect("failed to open log file");
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .with_writer(file)
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(true)
            .init();
    }
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("sqsshd-worker")
        .build()
        .expect("failed to build tokio runtime");

    rt.block_on(async {
        let cli = Cli::parse();
        init_logging(&cli);

        if let Err(e) = run(cli).await {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    });
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Load server config file
    let config_path = cli
        .config
        .as_deref()
        .unwrap_or_else(|| Path::new("/etc/sqssh/sqsshd.conf"));
    let mut server_config = ServerConfig::load(config_path)?;

    // CLI flags override config file
    if let Some(ref listen) = cli.listen {
        server_config.listen_address = listen.clone();
    }
    if let Some(port) = cli.port {
        server_config.port = port;
    }
    if let Some(ref hk) = cli.host_key {
        server_config.host_key = hk.clone();
    }
    if let Some(ref mode) = cli.auth_mode {
        server_config.auth_mode = match mode.as_str() {
            "whitelist+user" => AuthMode::WhitelistAndUser,
            "whitelist-only" => AuthMode::WhitelistOnly,
            "open+user" => AuthMode::OpenAndUser,
            _ => return Err(format!("invalid auth mode: {mode}").into()),
        };
    }

    if cli.no_migration {
        server_config.connection_migration = false;
    }

    let signing_key = keys::load_private_key(&server_config.host_key)?;
    let verifying_key = signing_key.verifying_key();

    if cli.show_pubkey {
        println!("{}", keys::encode_pubkey(&verifying_key));
        return Ok(());
    }

    // Load authorized_keys for all system users
    let authorized_keys =
        AuthorizedKeys::load_all_users(&server_config.authorized_keys_file)?;
    let ak_pubkeys = authorized_keys.all_pubkeys();

    tracing::info!(
        "loaded {} authorized key(s) from system users",
        ak_pubkeys.len()
    );

    // Convert Ed25519 pubkeys to X25519 for squic whitelist
    let whitelist_keys: Vec<[u8; 32]> = ak_pubkeys
        .iter()
        .filter_map(|ed_pub| ed25519_to_x25519(ed_pub))
        .collect();

    let addr: SocketAddr = format!("{}:{}", server_config.listen_address, server_config.port)
        .parse()?;

    let squic_config = squic::Config {
        alpn_protocols: vec![protocol::ALPN.to_vec()],
        keep_alive: Some(Duration::from_secs(15)),
        allowed_keys: if server_config.auth_mode != AuthMode::OpenAndUser {
            Some(whitelist_keys.clone())
        } else {
            None
        },
        disable_active_migration: !server_config.connection_migration,
        ..Default::default()
    };

    let listener = squic::listen(addr, &signing_key, squic_config).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!("sqsshd listening on {local_addr} (UDP)");
    tracing::info!("server pubkey: {}", keys::encode_pubkey(&verifying_key));
    tracing::info!("auth mode: {:?}", server_config.auth_mode);
    tracing::info!(
        "connection migration: {}",
        if server_config.connection_migration { "enabled" } else { "disabled" }
    );

    // Shutdown coordination
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let state = Arc::new(ServerState {
        authorized_keys: RwLock::new(authorized_keys),
        auth_mode: server_config.auth_mode,
        ak_relative: server_config.authorized_keys_file.clone(),
        listener,
        allow_users: server_config.allow_users.clone(),
        deny_users: server_config.deny_users.clone(),
        print_motd: server_config.print_motd,
        print_last_log: server_config.print_last_log,
        banner: server_config.banner.clone(),
        max_auth_tries: server_config.max_auth_tries,
        max_sessions: server_config.max_sessions,
        active_sessions: std::sync::atomic::AtomicUsize::new(0),
        pty_sessions: Mutex::new(HashMap::new()),
        next_session_id: std::sync::atomic::AtomicU64::new(1),
        pending_sessions: Mutex::new(HashMap::new()),
    });

    // Check for persisted sessions from a previous sqsshd instance
    recover_persisted_sessions(&state).await;

    // Spawn control socket listener
    let ctl_state = state.clone();
    let ctl_socket_path = server_config.control_socket.clone();
    let mut ctl_shutdown_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        if let Err(e) = run_control_socket(&ctl_socket_path, &ctl_state, &mut ctl_shutdown_rx).await
        {
            tracing::error!("control socket error: {e}");
        }
    });

    // Signal handlers
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigusr1 = signal(SignalKind::user_defined1())?;

    // Connection task tracker
    let mut tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            incoming = state.listener.accept() => {
                let incoming = match incoming {
                    Some(i) => i,
                    None => break,
                };

                let state = state.clone();
                tasks.spawn(async move {
                    // Determine remote address for span (from Incoming metadata)
                    let remote = incoming.remote_address();
                    let span = tracing::info_span!("conn", remote = %remote);
                    async {
                        if let Err(e) = handle_connection(incoming, state.clone()).await {
                            tracing::error!("connection error: {e}");
                        }
                    }
                    .instrument(span)
                    .await;
                });
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM, shutting down");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("received SIGINT, shutting down");
                break;
            }
            _ = sigusr1.recv() => {
                tracing::info!("received SIGUSR1, persisting sessions for restart");
                persist_sessions(&state).await;
                // Close listener and exit quickly — sessions are persisted
                state.listener.close(quinn::VarInt::from_u32(0), b"server restarting");
                shutdown_tx.send(true).ok();
                // Short drain to let disconnect messages send
                tokio::time::sleep(Duration::from_secs(1)).await;
                std::fs::remove_file(&server_config.control_socket).ok();
                tracing::info!("sqsshd shutdown complete (restart)");
                std::process::exit(0);
            }
            // Reap completed tasks
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }

    // Send SIGHUP to all child shell processes so they exit
    {
        let sessions = state.pty_sessions.lock().await;
        for (_, session) in sessions.iter() {
            unsafe { libc::kill(session.info.child_pid as i32, libc::SIGHUP); }
        }
    }

    // Watchdog: force exit after 5 seconds regardless of tokio state
    let ctl_sock = server_config.control_socket.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(5));
        std::fs::remove_file(&ctl_sock).ok();
        tracing::warn!("shutdown timeout, forcing exit");
        std::process::exit(0);
    });

    // Signal shutdown to all handlers
    shutdown_tx.send(true).ok();

    // Close the listener to stop new connections
    state
        .listener
        .close(quinn::VarInt::from_u32(0), b"server shutting down");

    // Wait for active tasks to finish (watchdog guarantees we exit within 5s)
    if !tasks.is_empty() {
        tracing::info!(
            "waiting for {} active connection(s) to finish...",
            tasks.len()
        );
        while tasks.join_next().await.is_some() {}
        tracing::info!("all connections drained");
    }

    // Clean up control socket
    std::fs::remove_file(&server_config.control_socket).ok();

    tracing::info!("sqsshd shutdown complete");
    std::process::exit(0);
}

// -- Control socket (sqsshctl communication) --

async fn run_control_socket(
    path: &Path,
    state: &ServerState,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create parent directory
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    // Remove stale socket
    tokio::fs::remove_file(path).await.ok();

    let ctl_listener = tokio::net::UnixListener::bind(path)?;

    // Allow any user to connect (peer_cred enforces per-user access)
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;

    tracing::info!("control socket: {}", path.display());

    loop {
        tokio::select! {
            result = ctl_listener.accept() => {
                let (stream, _) = result?;
                if let Err(e) = handle_ctl_connection(stream, state).await {
                    tracing::error!("control connection error: {e}");
                }
            }
            _ = shutdown_rx.changed() => {
                tracing::debug!("control socket shutting down");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_ctl_connection(
    stream: tokio::net::UnixStream,
    state: &ServerState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncWriteExt;

    // Get peer credentials
    let cred = stream.peer_cred()?;
    let peer_uid = cred.uid();

    // Read request (binary)
    let mut stream = stream;
    let request = CtlRequest::decode_async(&mut stream).await
        .map_err(|e| format!("invalid request: {e}"))?;

    let response = match request {
        CtlRequest::ReloadKeys => reload_user_keys(state, peer_uid).await,
        CtlRequest::ReloadAllKeys => {
            if peer_uid != 0 {
                CtlResponse::Error {
                    message: "only root can reload all keys".into(),
                }
            } else {
                reload_all_keys(state).await
            }
        }
    };

    // Send response (binary)
    let resp_data = response.encode();
    stream.write_all(&resp_data).await?;

    Ok(())
}

async fn reload_user_keys(state: &ServerState, uid: u32) -> CtlResponse {
    let username = match nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) {
        Ok(Some(user)) => user.name,
        Ok(None) => {
            return CtlResponse::Error {
                message: format!("unknown uid {uid}"),
            };
        }
        Err(e) => {
            return CtlResponse::Error {
                message: format!("failed to look up uid {uid}: {e}"),
            };
        }
    };

    let home = match nix::unistd::User::from_name(&username) {
        Ok(Some(user)) => user.dir.to_string_lossy().to_string(),
        _ => {
            return CtlResponse::Error {
                message: format!("could not find home for user '{username}'"),
            };
        }
    };

    let ak_path = PathBuf::from(&home).join(&state.ak_relative);
    let mut ak = state.authorized_keys.write().await;
    let old_pubkeys: Vec<[u8; 32]> = ak.all_pubkeys();

    if let Err(e) = ak.reload_user(&username, uid, &ak_path) {
        return CtlResponse::Error {
            message: format!("failed to reload keys for '{username}': {e}"),
        };
    }

    let new_pubkeys = ak.all_pubkeys();
    update_whitelist(state, &old_pubkeys, &new_pubkeys);

    CtlResponse::Ok {
        message: format!("reloaded keys for '{username}'"),
    }
}

async fn reload_all_keys(state: &ServerState) -> CtlResponse {
    let new_ak = match AuthorizedKeys::load_all_users(&state.ak_relative) {
        Ok(ak) => ak,
        Err(e) => {
            return CtlResponse::Error {
                message: format!("failed to reload keys: {e}"),
            };
        }
    };

    let mut ak = state.authorized_keys.write().await;
    let old_pubkeys = ak.all_pubkeys();
    let new_pubkeys = new_ak.all_pubkeys();

    update_whitelist(state, &old_pubkeys, &new_pubkeys);

    let count = new_pubkeys.len();
    *ak = new_ak;

    CtlResponse::Ok {
        message: format!("reloaded all keys ({count} total)"),
    }
}

fn update_whitelist(state: &ServerState, old_keys: &[[u8; 32]], new_keys: &[[u8; 32]]) {
    if state.auth_mode == AuthMode::OpenAndUser {
        return;
    }

    use std::collections::HashSet;
    let old_set: HashSet<[u8; 32]> = old_keys.iter().copied().collect();
    let new_set: HashSet<[u8; 32]> = new_keys.iter().copied().collect();

    for key in old_set.difference(&new_set) {
        if let Some(x25519) = ed25519_to_x25519(key) {
            state.listener.remove_key(&x25519);
            tracing::info!("whitelist: removed key");
        }
    }

    for key in new_set.difference(&old_set) {
        if let Some(x25519) = ed25519_to_x25519(key) {
            state.listener.allow_key(&x25519);
            tracing::info!("whitelist: added key");
        }
    }
}

// -- Session persistence --

async fn persist_sessions(state: &ServerState) {
    use sqssh_core::fdpass;
    use sqssh_core::persist::PersistPayload;

    let sessions = state.pty_sessions.lock().await;
    if sessions.is_empty() {
        tracing::info!("no active PTY sessions to persist");
        return;
    }

    // Start sqssh-persist helper
    let persist_result = std::process::Command::new("sqssh-persist")
        .spawn();

    let mut persist_child = match persist_result {
        Ok(child) => child,
        Err(e) => {
            tracing::error!("failed to start sqssh-persist: {e}");
            return;
        }
    };

    // Give it a moment to bind the socket
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connect to persist helper
    let stream = match std::os::unix::net::UnixStream::connect("/var/run/sqssh/persist.sock") {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("failed to connect to sqssh-persist: {e}");
            persist_child.kill().ok();
            return;
        }
    };

    let mut fds = Vec::new();
    let mut payload_sessions = Vec::new();

    for (_id, session) in sessions.iter() {
        fds.push(session.master_fd);
        payload_sessions.push(session.info.clone());
    }

    let payload = PersistPayload {
        sessions: payload_sessions,
    };

    let data = match payload.encode() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("failed to encode persist payload: {e}");
            return;
        }
    };

    if let Err(e) = fdpass::send_fds(&stream, &fds, &data) {
        tracing::error!("failed to send fds to sqssh-persist: {e}");
        return;
    }

    tracing::info!("persisted {} session(s) to sqssh-persist", fds.len());
}

async fn recover_persisted_sessions(state: &ServerState) {
    use sqssh_core::fdpass;
    use sqssh_core::persist::PersistPayload;

    // Try to connect to existing sqssh-persist
    let stream = match std::os::unix::net::UnixStream::connect("/var/run/sqssh/persist.sock") {
        Ok(s) => s,
        Err(_) => return, // No persist helper running — normal startup
    };

    tracing::info!("found sqssh-persist, recovering sessions...");

    let (fds, data) = match fdpass::recv_fds(&stream, 256) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("failed to receive from sqssh-persist: {e}");
            return;
        }
    };

    let payload = match PersistPayload::decode(&data) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("failed to decode persist payload: {e}");
            return;
        }
    };

    if fds.len() != payload.sessions.len() {
        tracing::error!(
            "fd count ({}) doesn't match session count ({})",
            fds.len(),
            payload.sessions.len()
        );
        return;
    }

    let mut pending = state.pending_sessions.lock().await;

    for (i, session) in payload.sessions.into_iter().enumerate() {
        let fd = fds[i];

        // Verify child process is still alive
        let alive = unsafe { libc::kill(session.child_pid as i32, 0) } == 0;
        if !alive {
            tracing::warn!(
                "session for user '{}' (pid {}) is dead, skipping",
                session.username,
                session.child_pid
            );
            unsafe { libc::close(fd); }
            continue;
        }

        tracing::info!(
            "recovered session: user={}, pid={}, fd={}",
            session.username,
            session.child_pid,
            fd
        );

        let key = (session.client_pubkey, session.username.clone());
        pending.insert(key, (fd, session));
    }

    tracing::info!("recovered {} pending session(s)", pending.len());
}

// -- Connection handling --

async fn handle_connection(
    incoming: quinn::Incoming,
    state: Arc<ServerState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = incoming.await?;
    let remote = conn.remote_address();
    tracing::info!("connected");

    // Accept auth stream (stream 0) — raw binary protocol
    let (mut auth_send, mut auth_recv) = conn.accept_bi().await
        .map_err(|e| format!("failed to accept auth stream: {e}"))?;

    // Auth loop with MaxAuthTries
    let mut auth_attempts = 0usize;
    let (username, pubkey_bytes) = loop {
        // Read type byte
        let mut type_buf = [0u8; 1];
        auth_recv.read_exact(&mut type_buf).await
            .map_err(|e| format!("auth type byte: {e}"))?;

        if type_buf[0] != protocol::AUTH_REQUEST {
            tracing::warn!("expected AUTH_REQUEST, got {:#x}", type_buf[0]);
            return Ok(());
        }

        let auth_data = protocol::decode_auth_request(&mut auth_recv).await?;
        let username = auth_data.username;
        let pubkey_bytes = auth_data.pubkey;
        tracing::info!(user = %username, "auth request");

        auth_attempts += 1;

        // Check AllowUsers
        if !state.allow_users.is_empty() && !state.allow_users.contains(&username) {
            tracing::warn!(user = %username, "rejected by AllowUsers");
            auth_send
                .write_all(&protocol::encode_auth_failure("user not allowed"))
                .await?;
            if auth_attempts >= state.max_auth_tries {
                tracing::warn!("max auth tries exceeded");
                return Ok(());
            }
            continue;
        }

        // Check DenyUsers
        if state.deny_users.contains(&username) {
            tracing::warn!(user = %username, "rejected by DenyUsers");
            auth_send
                .write_all(&protocol::encode_auth_failure("user denied"))
                .await?;
            if auth_attempts >= state.max_auth_tries {
                tracing::warn!("max auth tries exceeded");
                return Ok(());
            }
            continue;
        }

        // Validate auth based on mode
        let authorized = match state.auth_mode {
            AuthMode::WhitelistAndUser | AuthMode::OpenAndUser => {
                let vk = VerifyingKey::from_bytes(&pubkey_bytes)
                    .map_err(|_| "invalid ed25519 pubkey")?;
                let ak = state.authorized_keys.read().await;
                ak.is_authorized(&vk, &username)
            }
            AuthMode::WhitelistOnly => true,
        };

        if authorized {
            break (username, pubkey_bytes);
        }

        tracing::warn!(user = %username, "auth rejected");
        auth_send
            .write_all(&protocol::encode_auth_failure("pubkey not authorized for this user"))
            .await?;

        if auth_attempts >= state.max_auth_tries {
            tracing::warn!("max auth tries exceeded, disconnecting");
            return Ok(());
        }
    };

    auth_send
        .write_all(&protocol::encode_auth_success())
        .await?;
    tracing::info!(user = %username, "auth success");

    // Check for a pending persisted session
    let pending_key = (pubkey_bytes, username.clone());
    let mut pending_session = {
        let mut pending = state.pending_sessions.lock().await;
        pending.remove(&pending_key)
    };

    // Read banner file content for sending on first session channel
    let banner_content = state.banner.as_ref().and_then(|path| {
        std::fs::read_to_string(path).ok()
    });

    // Spawn migration monitor
    let migration_conn = conn.clone();
    let migration_remote = remote;
    tokio::spawn(
        async move {
            let mut last = migration_remote;
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let current = migration_conn.remote_address();
                if current != last {
                    tracing::info!(
                        from = %last,
                        to = %current,
                        "client migrated"
                    );
                    last = current;
                }
            }
        }
        .in_current_span(),
    );

    // Track upload task handles so sync can wait for completion
    let upload_handles: Arc<tokio::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    // Handle channel requests (bidi) and raw file transfers (uni)
    loop {
        let accept_result = tokio::select! {
            bidi = conn.accept_bi() => {
                match bidi {
                    Ok((send, mut recv)) => {
                        // Peek at the first bytes to determine stream type.
                        // Raw shell streams start with RAW_SHELL (0xB0) or SHELL_CONTROL (0xB1).
                        // Framed channel streams start with a 4-byte length prefix.
                        let mut peek = [0u8; 1];
                        match recv.read_exact(&mut peek).await {
                            Ok(()) => {
                                match peek[0] {
                                    protocol::RAW_SHELL => {
                                        match protocol::RawShellHeader::decode(&mut recv).await {
                                            Ok(header) => AcceptResult::RawShell(send, recv, header),
                                            Err(e) => {
                                                tracing::error!("raw shell header: {e}");
                                                continue;
                                            }
                                        }
                                    }
                                    protocol::SHELL_CONTROL => {
                                        AcceptResult::ShellControl
                                    }
                                    protocol::RAW_SFTP => {
                                        AcceptResult::RawSftp(send, recv)
                                    }
                                    protocol::RAW_EXEC => {
                                        // Read command: [2 bytes cmd_len][command]
                                        let mut cmd_len_buf = [0u8; 2];
                                        if let Err(e) = recv.read_exact(&mut cmd_len_buf).await {
                                            tracing::error!("exec cmd len: {e}");
                                            continue;
                                        }
                                        let cmd_len = u16::from_be_bytes(cmd_len_buf) as usize;
                                        let mut cmd_buf = vec![0u8; cmd_len];
                                        if let Err(e) = recv.read_exact(&mut cmd_buf).await {
                                            tracing::error!("exec cmd: {e}");
                                            continue;
                                        }
                                        let command = String::from_utf8(cmd_buf).unwrap_or_default();
                                        AcceptResult::RawExec(send, recv, command)
                                    }
                                    protocol::RAW_DOWNLOAD_REQUEST => {
                                        // Read: [2 bytes path_len][path][4 bytes jobs]
                                        match protocol::decode_path(&mut recv).await {
                                            Ok(path) => {
                                                let mut jobs_buf = [0u8; 4];
                                                if let Err(e) = recv.read_exact(&mut jobs_buf).await {
                                                    tracing::error!("download jobs: {e}");
                                                    continue;
                                                }
                                                let jobs = u32::from_be_bytes(jobs_buf);
                                                AcceptResult::RawDownloadRequest(send, recv, path, jobs)
                                            }
                                            Err(e) => {
                                                tracing::error!("download path: {e}");
                                                continue;
                                            }
                                        }
                                    }
                                    0xFE => {
                                        // Sync request — client wants to know all prior uni streams are done.
                                        // Read expected file count, wait for all upload tasks, then reply.
                                        let mut sync_send = send;
                                        let upload_handles_clone = upload_handles.clone();
                                        tokio::spawn(async move {
                                            // Read expected count
                                            let mut count_buf = [0u8; 4];
                                            let _ = recv.read_exact(&mut count_buf).await;
                                            let _expected = u32::from_be_bytes(count_buf);
                                            // Wait for all in-flight upload tasks
                                            {
                                                let mut handles = upload_handles_clone.lock().await;
                                                for handle in handles.drain(..) {
                                                    let _ = handle.await;
                                                }
                                            }
                                            let _ = sync_send.write_all(&[0xFE]).await;
                                            let _ = sync_send.finish();
                                        });
                                        continue;
                                    }
                                    other => {
                                        tracing::warn!("unknown bidi stream type: {other:#x}");
                                        continue;
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    Err(_) => break,
                }
            }
            uni = conn.accept_uni() => {
                match uni {
                    Ok(recv) => AcceptResult::Uni(recv),
                    Err(_) => break,
                }
            }
        };

        match accept_result {
            AcceptResult::Uni(mut recv) => {
                let user = username.clone();
                let handle = tokio::spawn(async move {
                    let mut type_buf = [0u8; 1];
                    if let Err(e) = recv.read_exact(&mut type_buf).await {
                        tracing::error!("failed to read uni stream type: {e}");
                        return;
                    }
                    match type_buf[0] {
                        protocol::RAW_UPLOAD => {
                            if let Err(e) = file_handler::handle_raw_upload(recv, &user).await {
                                tracing::error!("raw upload error: {e}");
                            }
                        }
                        protocol::RAW_UPLOAD_CHUNK => {
                            if let Err(e) = file_handler::handle_raw_upload_chunk(recv, &user).await {
                                tracing::error!("raw chunk upload error: {e}");
                            }
                        }
                        other => {
                            tracing::warn!("unknown uni stream type: {other:#x}");
                        }
                    }
                }.in_current_span());
                upload_handles.lock().await.push(handle);
                continue;
            }
            AcceptResult::RawShell(data_send, data_recv, header) => {
                // Raw shell session — wait for the control stream to arrive
                // Store the pending raw shell and pick it up when ShellControl arrives
                use std::sync::atomic::Ordering::Relaxed;
                let current = state.active_sessions.fetch_add(1, Relaxed);
                if current >= state.max_sessions {
                    state.active_sessions.fetch_sub(1, Relaxed);
                    tracing::warn!("max sessions ({}) reached, rejecting raw shell", state.max_sessions);
                    continue;
                }

                // We need the control stream — it should be the next bidi stream.
                // For now, accept it inline (client opens data then control immediately).
                let ctrl_result = conn.accept_bi().await;
                let (ctrl_send, mut ctrl_recv) = match ctrl_result {
                    Ok(pair) => pair,
                    Err(_) => {
                        state.active_sessions.fetch_sub(1, Relaxed);
                        break;
                    }
                };
                // Read and verify the SHELL_CONTROL type byte
                let mut ctrl_type = [0u8; 1];
                if let Err(e) = ctrl_recv.read_exact(&mut ctrl_type).await {
                    tracing::error!("shell control type: {e}");
                    state.active_sessions.fetch_sub(1, Relaxed);
                    continue;
                }
                if ctrl_type[0] != protocol::SHELL_CONTROL {
                    tracing::error!("expected SHELL_CONTROL, got {:#x}", ctrl_type[0]);
                    state.active_sessions.fetch_sub(1, Relaxed);
                    continue;
                }

                let user = username.clone();
                let remote_host = remote.ip().to_string();
                let print_motd = state.print_motd;
                let print_last_log = state.print_last_log;
                let banner = banner_content.clone();
                let state_ref = state.clone();
                let client_pk = pubkey_bytes;
                let resumed_fd = pending_session.take().map(|(fd, info)| {
                    tracing::info!(
                        user = %info.username,
                        pid = info.child_pid,
                        "resuming persisted session (raw)"
                    );
                    (fd, info)
                });
                tokio::spawn(
                    async move {
                        if let Some((fd, info)) = resumed_fd {
                            if let Err(e) = pty_handler::resume_raw_shell(
                                data_send, data_recv, ctrl_send, ctrl_recv,
                                fd, info.child_pid,
                                header.cols as u16, header.rows as u16,
                            ).await {
                                tracing::error!("raw resume error: {e}");
                            }
                        } else if let Err(e) = handle_raw_session_with_persist(
                            data_send, data_recv, ctrl_send, ctrl_recv,
                            &header, &user, &remote_host,
                            print_motd, print_last_log, banner,
                            &state_ref, client_pk,
                        ).await {
                            tracing::error!("raw session error: {e}");
                        }
                        state_ref.active_sessions.fetch_sub(1, Relaxed);
                    }
                    .in_current_span(),
                );
                continue;
            }
            AcceptResult::ShellControl => {
                // Shell control without preceding raw shell — ignore
                tracing::warn!("received ShellControl without RawShell");
                continue;
            }
            AcceptResult::RawSftp(mut sftp_send, mut sftp_recv) => {
                let user = username.clone();
                let conn_for_sftp = conn.clone();
                tokio::spawn(
                    async move {
                        if let Err(e) = sftp_handler::handle_sftp(
                            &mut sftp_send, &mut sftp_recv, &conn_for_sftp, &user,
                        ).await {
                            tracing::error!("raw sftp error: {e}");
                        }
                    }
                    .in_current_span(),
                );
                continue;
            }
            AcceptResult::RawExec(exec_send, exec_recv, command) => {
                let user = username.clone();
                let conn_for_exec = conn.clone();
                tokio::spawn(
                    async move {
                        if let Err(e) = pty_handler::run_raw_exec(
                            exec_send, exec_recv, &conn_for_exec, &user, &command,
                        ).await {
                            tracing::error!(cmd = %command, "raw exec error: {e}");
                        }
                    }
                    .in_current_span(),
                );
                continue;
            }
            AcceptResult::RawDownloadRequest(dl_send, dl_recv, path, jobs) => {
                let user = username.clone();
                let conn_ref = conn.clone();
                tokio::spawn(
                    async move {
                        if let Err(e) = file_handler::handle_raw_download(
                            &conn_ref, dl_send, dl_recv, &user, &path, jobs,
                        ).await {
                            tracing::error!(path = %path, "raw download error: {e}");
                        }
                    }
                    .in_current_span(),
                );
                continue;
            }
        }
    }

    tracing::info!("disconnected");
    Ok(())
}

async fn handle_raw_session_with_persist(
    data_send: quinn::SendStream,
    data_recv: quinn::RecvStream,
    ctrl_send: quinn::SendStream,
    ctrl_recv: quinn::RecvStream,
    header: &protocol::RawShellHeader,
    username: &str,
    remote_host: &str,
    print_motd: bool,
    print_last_log: bool,
    banner: Option<String>,
    state: &Arc<ServerState>,
    client_pubkey: [u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let user = username.to_string();
    let term = header.term.clone();
    let cols = header.cols as u16;
    let rows = header.rows as u16;
    let session_id = state.next_session_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let (spawn_tx, spawn_rx) = tokio::sync::oneshot::channel::<ActivePtySession>();

    let state_for_reg = state.clone();
    tokio::spawn(async move {
        if let Ok(session) = spawn_rx.await {
            state_for_reg.pty_sessions.lock().await.insert(session_id, session);
        }
    });

    let term_clone = term.clone();
    pty_handler::run_raw_shell(
        data_send, data_recv, ctrl_send, ctrl_recv,
        username, remote_host, &term, cols, rows, print_motd, print_last_log,
        banner,
        move |spawned| {
            let info = PersistedSession {
                username: user.clone(),
                client_pubkey,
                term: term_clone.clone(),
                cols,
                rows,
                child_pid: spawned.child_pid,
                home: spawned.home.clone(),
                shell: spawned.shell.clone(),
            };
            tracing::info!(
                session_id,
                pid = spawned.child_pid,
                fd = spawned.master_raw_fd,
                "registered raw PTY session for persistence"
            );
            let _ = spawn_tx.send(ActivePtySession {
                info,
                master_fd: spawned.master_raw_fd,
            });
        },
    ).await
}
