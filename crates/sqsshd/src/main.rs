use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use ed25519_dalek::VerifyingKey;
use sqssh_core::auth::{AuthMode, AuthorizedKeys};
use sqssh_core::config::ServerConfig;
use sqssh_core::keys;
use sqssh_core::protocol::{self, ChannelMsg, ChannelType, ControlMsg};
use sqssh_core::stream::{Channel, ControlChannel};
use tokio::sync::RwLock;

mod pty_handler;

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

    /// Show the server's public key and exit
    #[arg(long = "show-pubkey")]
    show_pubkey: bool,
}

/// Shared server state passed to connection handlers.
struct ServerState {
    authorized_keys: RwLock<AuthorizedKeys>,
    auth_mode: AuthMode,
    ak_relative: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Load server config file
    let config_path = cli
        .config
        .as_deref()
        .unwrap_or_else(|| std::path::Path::new("/etc/sqssh/sqsshd.conf"));
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

    eprintln!(
        "loaded {} authorized key(s) from system users",
        ak_pubkeys.len()
    );

    // Convert Ed25519 pubkeys to X25519 for squic whitelist
    let whitelist_keys: Vec<[u8; 32]> = ak_pubkeys
        .iter()
        .filter_map(|ed_pub| {
            squic::crypto::ed25519_public_to_x25519(ed_pub)
                .ok()
                .map(|xpub| xpub.to_bytes())
        })
        .collect();

    let addr: SocketAddr = format!("{}:{}", server_config.listen_address, server_config.port)
        .parse()?;

    let squic_config = squic::Config {
        alpn_protocols: vec![protocol::ALPN.to_vec()],
        keep_alive: Some(std::time::Duration::from_secs(15)),
        allowed_keys: if server_config.auth_mode != AuthMode::OpenAndUser {
            Some(whitelist_keys.clone())
        } else {
            None
        },
        ..Default::default()
    };

    let listener = squic::listen(addr, &signing_key, squic_config).await?;
    let local_addr = listener.local_addr()?;
    eprintln!("sqsshd listening on {local_addr} (UDP)");
    eprintln!("server pubkey: {}", keys::encode_pubkey(&verifying_key));
    eprintln!("auth mode: {:?}", server_config.auth_mode);

    let state = Arc::new(ServerState {
        authorized_keys: RwLock::new(authorized_keys),
        auth_mode: server_config.auth_mode,
        ak_relative: server_config.authorized_keys_file.clone(),
    });

    loop {
        let incoming = match listener.accept().await {
            Some(incoming) => incoming,
            None => break,
        };

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, &state).await {
                tracing::error!("connection error: {e}");
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    incoming: quinn::Incoming,
    state: &ServerState,
) -> Result<(), Box<dyn std::error::Error>> {
    let conn = incoming.await?;
    let remote = conn.remote_address();
    tracing::info!("new connection from {remote}");

    // Accept control channel (stream 0)
    let mut control = ControlChannel::accept(&conn).await?;

    let auth_msg = control.recv().await?;
    let (username, pubkey_bytes) = match auth_msg {
        ControlMsg::AuthRequest {
            username, pubkey, ..
        } => {
            tracing::info!("auth request from user '{username}'");
            let pubkey_bytes: [u8; 32] = pubkey
                .try_into()
                .map_err(|_| "invalid pubkey length")?;
            (username, pubkey_bytes)
        }
        other => {
            tracing::warn!("expected AuthRequest, got {other:?}");
            return Ok(());
        }
    };

    // Validate auth based on mode
    match state.auth_mode {
        AuthMode::WhitelistAndUser | AuthMode::OpenAndUser => {
            let vk = VerifyingKey::from_bytes(&pubkey_bytes)
                .map_err(|_| "invalid ed25519 pubkey")?;
            let ak = state.authorized_keys.read().await;
            if !ak.is_authorized(&vk, &username) {
                tracing::warn!("auth rejected: pubkey not authorized for user '{username}'");
                control
                    .send(&ControlMsg::AuthFailure {
                        message: "pubkey not authorized for this user".into(),
                    })
                    .await?;
                return Ok(());
            }
        }
        AuthMode::WhitelistOnly => {
            // Client already passed squic whitelist — no user check needed
        }
    }

    control.send(&ControlMsg::AuthSuccess).await?;
    tracing::info!("auth success for '{username}'");

    // Handle channel requests
    loop {
        let (mut channel, channel_type) = match Channel::accept(&conn).await {
            Ok(v) => v,
            Err(_) => break,
        };

        match channel_type {
            ChannelType::Session => {
                channel.confirm().await?;
                let user = username.clone();
                let remote_host = remote.ip().to_string();
                tokio::spawn(async move {
                    if let Err(e) = handle_session(channel, &user, &remote_host).await {
                        tracing::error!("session error: {e}");
                    }
                });
            }
            other => {
                tracing::warn!("unsupported channel type: {other:?}");
                channel.reject(1, "unsupported channel type").await?;
            }
        }
    }

    tracing::info!("connection from {remote} closed");
    Ok(())
}

async fn handle_session(
    mut channel: Channel,
    username: &str,
    remote_host: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut term = String::from("xterm-256color");
    let mut cols: u16 = 80;
    let mut rows: u16 = 24;

    loop {
        let msg = channel.recv().await?;
        match msg {
            ChannelMsg::PtyRequest {
                term: t,
                cols: c,
                rows: r,
            } => {
                term = t;
                cols = c as u16;
                rows = r as u16;
                channel.send(&ChannelMsg::PtySuccess).await?;
            }
            ChannelMsg::ShellRequest => {
                break;
            }
            ChannelMsg::ExecRequest { command } => {
                pty_handler::run_exec(&mut channel, username, &command).await?;
                return Ok(());
            }
            other => {
                tracing::debug!("ignoring pre-shell message: {other:?}");
            }
        }
    }

    // Spawn shell with PTY
    pty_handler::run_shell(&mut channel, username, remote_host, &term, cols, rows).await
}
