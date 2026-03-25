use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use sqssh_core::config::ClientConfig;
use sqssh_core::keys;
use sqssh_core::known_hosts::KnownHosts;
use sqssh_core::protocol::{self, RawShellHeader, ShellControlHeader, ShellControlMsg};
use tokio::io::AsyncWriteExt;

#[derive(Parser)]
#[command(name = "sqssh", about = "sqssh remote shell client")]
struct Cli {
    /// [user@]hostname
    destination: String,

    /// Remote command to execute
    command: Vec<String>,

    /// Port (UDP)
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Identity file (private key)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Verbose mode (enables debug logging)
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let level = if cli.verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(level).unwrap_or_default(),
        )
        .with_target(false)
        .init();

    if let Err(e) = run(cli).await {
        eprintln!("sqssh: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // Parse user@host
    let (user, host) = parse_destination(&cli.destination)?;

    // Load config
    let sqssh_dir = keys::sqssh_dir()?;
    let config = ClientConfig::load(&sqssh_dir.join("config"))?;
    let resolved = config.resolve(&host);

    let actual_host = resolved.hostname.as_deref().unwrap_or(&host);
    let port = cli.port.unwrap_or(resolved.port);
    let user = user
        .or(resolved.user.clone())
        .unwrap_or_else(|| whoami::username());

    // Resolve server public key
    let server_pubkey = if let Some(ref hk) = resolved.host_key {
        keys::decode_pubkey(hk)?
    } else {
        let known_hosts = KnownHosts::load(&sqssh_dir.join("known_hosts"))?;
        *known_hosts.lookup(actual_host).ok_or_else(|| {
            sqssh_core::error::Error::UnknownHost(actual_host.to_string())
        })?
    };

    // Resolve address
    let addr: SocketAddr = format!("{actual_host}:{port}")
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| sqssh_core::error::Error::Connection(
            format!("could not resolve {actual_host}:{port}")
        ))?;

    // Load identity key
    let identity_path = cli
        .identity
        .clone()
        .or(resolved.identity_file.map(PathBuf::from))
        .unwrap_or_else(|| sqssh_dir.join("id_ed25519"));
    let signing_key = keys::load_private_key(&identity_path)?;
    let verifying_key = signing_key.verifying_key();

    // Connect via squic with client identity for whitelist auth
    let client_key_hex = signing_key
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let squic_config = squic::Config {
        alpn_protocols: vec![protocol::ALPN.to_vec()],
        keep_alive: Some(std::time::Duration::from_secs(resolved.keepalive_interval)),
        client_key: Some(client_key_hex),
        handshake_timeout: Some(std::time::Duration::from_secs(resolved.connect_timeout)),
        ..Default::default()
    };

    let conn = squic::dial(addr, server_pubkey.as_bytes(), squic_config)
        .await
        .map_err(|e| {
            let hint = sqssh_core::error::format_connection_error(&e.to_string());
            format!("{hint}")
        })?;

    // Authenticate on stream 0 (raw binary)
    let (mut auth_send, mut auth_recv) = conn.open_bi().await?;
    auth_send
        .write_all(&protocol::encode_auth_request(&user, verifying_key.as_bytes()))
        .await?;

    match protocol::decode_auth_response(&mut auth_recv).await? {
        protocol::AuthResponseData::Success => {
            // Auto-learn key mapping for this host
            if let Some(key_name) = identity_path.file_name() {
                keys::save_key_mapping(&host, &key_name.to_string_lossy()).ok();
            }
        }
        protocol::AuthResponseData::Failure { message } => {
            return Err(format!("authentication failed: {message}").into());
        }
    }

    if !cli.command.is_empty() {
        let cmd = cli.command.join(" ");
        return run_remote_command(&conn, &cmd).await;
    }

    // Interactive shell via raw QUIC streams
    run_raw_shell(&conn, &signing_key).await
}

async fn reconnect_raw_shell(
    stdin_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    cached_key: &ed25519_dalek::SigningKey,
) -> Result<i32, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let (user, host) = parse_destination(&cli.destination)?;
    let sqssh_dir = keys::sqssh_dir()?;
    let config = ClientConfig::load(&sqssh_dir.join("config"))?;
    let resolved = config.resolve(&host);

    let actual_host = resolved.hostname.as_deref().unwrap_or(&host);
    let port = cli.port.unwrap_or(resolved.port);
    let user = user
        .or(resolved.user.clone())
        .unwrap_or_else(|| whoami::username());

    let server_pubkey = if let Some(ref hk) = resolved.host_key {
        keys::decode_pubkey(hk)?
    } else {
        let known_hosts = KnownHosts::load(&sqssh_dir.join("known_hosts"))?;
        *known_hosts.lookup(actual_host).ok_or_else(|| {
            sqssh_core::error::Error::UnknownHost(actual_host.to_string())
        })?
    };

    let addr: SocketAddr = format!("{actual_host}:{port}")
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve address")?;

    let signing_key = cached_key.clone();
    let verifying_key = signing_key.verifying_key();

    let client_key_hex = signing_key
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let squic_config = squic::Config {
        alpn_protocols: vec![protocol::ALPN.to_vec()],
        keep_alive: Some(Duration::from_secs(resolved.keepalive_interval)),
        client_key: Some(client_key_hex),
        handshake_timeout: Some(Duration::from_millis(1500)),
        ..Default::default()
    };

    let conn = squic::dial(addr, server_pubkey.as_bytes(), squic_config).await?;

    let (mut auth_send, mut auth_recv) = conn.open_bi().await?;
    auth_send
        .write_all(&protocol::encode_auth_request(&user, verifying_key.as_bytes()))
        .await?;

    match protocol::decode_auth_response(&mut auth_recv).await? {
        protocol::AuthResponseData::Success => {}
        protocol::AuthResponseData::Failure { message } => {
            return Err(format!("authentication failed: {message}").into());
        }
    }

    eprintln!("Reconnected.");

    let (data_send, data_recv, ctrl_send, ctrl_recv) = open_raw_shell(&conn).await?;

    let orig_termios = set_raw_mode()?;
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }

    let result = relay_raw_stdio(data_send, data_recv, ctrl_send, ctrl_recv, stdin_rx).await;

    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGQUIT, libc::SIG_DFL);
    }
    restore_terminal(&orig_termios);

    conn.close(quinn::VarInt::from_u32(0), b"client disconnect");

    result
}

async fn open_raw_shell(
    conn: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::RecvStream, quinn::SendStream, quinn::RecvStream), Box<dyn std::error::Error>> {
    let (cols, rows) = term_size();
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());

    // Open data stream (raw bidi for stdin/stdout)
    let (mut data_send, data_recv) = conn.open_bi().await?;
    let header = RawShellHeader { term, cols: cols as u32, rows: rows as u32 };
    data_send.write_all(&header.encode()).await?;

    // Open control stream (for window change, exit status)
    let (mut ctrl_send, ctrl_recv) = conn.open_bi().await?;
    ctrl_send.write_all(&ShellControlHeader::encode()).await?;

    Ok((data_send, data_recv, ctrl_send, ctrl_recv))
}

/// Spawn a single stdin reader thread that lives for the process lifetime.
fn spawn_stdin_reader() -> tokio::sync::mpsc::Receiver<Vec<u8>> {
    let (stdin_tx, stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut buf = vec![0u8; 4096];
        loop {
            match std::io::stdin().read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdin_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    stdin_rx
}

async fn run_raw_shell(
    conn: &quinn::Connection,
    cached_key: &ed25519_dalek::SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let (data_send, data_recv, ctrl_send, ctrl_recv) = open_raw_shell(conn).await?;

    let orig_termios = set_raw_mode()?;
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGQUIT, libc::SIG_IGN);
    }

    let mut stdin_rx = spawn_stdin_reader();
    let result = relay_raw_stdio(data_send, data_recv, ctrl_send, ctrl_recv, &mut stdin_rx).await;

    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGQUIT, libc::SIG_DFL);
    }
    restore_terminal(&orig_termios);

    match &result {
        Err(e) => {
            let msg = e.to_string();

            if msg.contains("server restarting") {
                conn.close(quinn::VarInt::from_u32(0), b"reconnecting");
                eprintln!("\r\nServer restarting. Reconnecting...");
            } else if msg.contains("server shutting down")
                || msg.contains("application close")
            {
                eprintln!("\r\nConnection closed by remote host.");
                conn.close(quinn::VarInt::from_u32(0), b"");
                std::process::exit(0);
            } else if msg.contains("connection lost")
                || msg.contains("stream finished")
                || msg.contains("timed out")
            {
                eprintln!("\r\nConnection lost.");
                conn.close(quinn::VarInt::from_u32(0), b"");
                std::process::exit(1);
            } else {
                conn.close(quinn::VarInt::from_u32(0), b"");
                eprintln!("\r\nsqssh: {msg}");
                std::process::exit(1);
            }

            // Reconnect loop (only reached for "server restarting")
            let mut attempt = 0u32;
            loop {
                let delay = if attempt == 0 {
                    Duration::from_millis(500)
                } else {
                    Duration::from_secs((1 << (attempt - 1).min(4)) as u64)
                };
                tokio::time::sleep(delay).await;
                attempt += 1;

                match reconnect_raw_shell(&mut stdin_rx, cached_key).await {
                    Ok(code) => std::process::exit(code),
                    Err(_) => {
                        eprint!(".");
                    }
                }
            }
        }
        _ => {}
    }

    conn.close(quinn::VarInt::from_u32(0), b"client disconnect");

    match result {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("sqssh: {e}");
            std::process::exit(1);
        }
    }
}

async fn run_remote_command(
    conn: &quinn::Connection,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Open bidi stream: [RAW_EXEC][2 bytes cmd_len][command]
    let (mut send, mut recv) = conn.open_bi().await?;
    let cmd_bytes = command.as_bytes();
    let mut header = Vec::with_capacity(1 + 2 + cmd_bytes.len());
    header.push(protocol::RAW_EXEC);
    header.extend_from_slice(&(cmd_bytes.len() as u16).to_be_bytes());
    header.extend_from_slice(cmd_bytes);
    send.write_all(&header).await?;
    send.finish()?;

    // Accept stderr uni stream from server
    let conn_clone = conn.clone();
    let stderr_task = tokio::spawn(async move {
        if let Ok(mut uni_recv) = conn_clone.accept_uni().await {
            let mut type_buf = [0u8; 1];
            if uni_recv.read_exact(&mut type_buf).await.is_ok()
                && type_buf[0] == protocol::RAW_EXEC_STDERR
            {
                let mut buf = vec![0u8; 8192];
                loop {
                    match uni_recv.read(&mut buf).await {
                        Ok(Some(n)) => {
                            let mut stderr = tokio::io::stderr();
                            let _ = stderr.write_all(&buf[..n]).await;
                            let _ = stderr.flush().await;
                        }
                        _ => break,
                    }
                }
            }
        }
    });

    // Read stdout from bidi recv, holding back a 4-byte tail for exit code.
    // Server writes: [raw stdout bytes...][4 bytes exit_code] then finishes.
    let mut tail = Vec::new();
    let mut buf = vec![0u8; 8192];

    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                tail.extend_from_slice(&buf[..n]);
                if tail.len() > 4 {
                    let flush_len = tail.len() - 4;
                    let mut stdout = tokio::io::stdout();
                    stdout.write_all(&tail[..flush_len]).await?;
                    stdout.flush().await?;
                    tail.drain(..flush_len);
                }
            }
            Ok(None) => break,
            Err(e) => return Err(format!("read error: {e}").into()),
        }
    }

    stderr_task.abort();

    // Extract exit code from last 4 bytes
    let exit_code = if tail.len() >= 4 {
        let off = tail.len() - 4;
        u32::from_be_bytes([tail[off], tail[off + 1], tail[off + 2], tail[off + 3]])
    } else {
        0
    };

    if exit_code != 0 {
        std::process::exit(exit_code as i32);
    }
    Ok(())
}

/// Escape sequence state machine.
enum EscapeState {
    Normal,
    /// Last byte was a newline (or start of connection).
    AfterNewline,
    /// Saw ~ after newline, waiting for next byte.
    SawTilde,
}

async fn relay_raw_stdio(
    mut data_send: quinn::SendStream,
    mut data_recv: quinn::RecvStream,
    mut ctrl_send: quinn::SendStream,
    mut ctrl_recv: quinn::RecvStream,
    stdin_rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<i32, Box<dyn std::error::Error>> {
    let mut exit_code = 0i32;
    let mut escape = EscapeState::AfterNewline;

    // Spawn SIGWINCH handler
    let (winch_tx, mut winch_rx) = tokio::sync::mpsc::channel::<(u32, u32)>(4);
    tokio::spawn(async move {
        let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).unwrap();
        loop {
            sig.recv().await;
            let (cols, rows) = term_size();
            if winch_tx.send((cols as u32, rows as u32)).await.is_err() {
                break;
            }
        }
    });

    // Read buffer for data_recv
    let mut recv_buf = vec![0u8; 8192];

    loop {
        tokio::select! {
            biased;

            // Server → stdout (raw bytes)
            n = data_recv.read(&mut recv_buf) => {
                match n {
                    Ok(Some(n)) => {
                        let mut stdout = tokio::io::stdout();
                        stdout.write_all(&recv_buf[..n]).await?;
                        stdout.flush().await?;
                    }
                    Ok(None) => break, // stream finished
                    Err(e) => return Err(format!("connection lost: {e}").into()),
                }
            }

            // Control messages from server (exit status, etc.)
            ctrl = ShellControlMsg::decode(&mut ctrl_recv) => {
                match ctrl {
                    Ok(ShellControlMsg::ExitStatus { code }) => {
                        exit_code = code as i32;
                    }
                    Ok(ShellControlMsg::Eof) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }

            // stdin → server (raw bytes)
            data = stdin_rx.recv() => {
                match data {
                    Some(payload) => {
                        let mut send_buf = Vec::with_capacity(payload.len());
                        let mut should_disconnect = false;

                        for &byte in &payload {
                            match escape {
                                EscapeState::Normal => {
                                    if byte == b'\r' || byte == b'\n' {
                                        escape = EscapeState::AfterNewline;
                                    }
                                    send_buf.push(byte);
                                }
                                EscapeState::AfterNewline => {
                                    if byte == b'~' {
                                        escape = EscapeState::SawTilde;
                                    } else {
                                        if byte == b'\r' || byte == b'\n' {
                                            escape = EscapeState::AfterNewline;
                                        } else {
                                            escape = EscapeState::Normal;
                                        }
                                        send_buf.push(byte);
                                    }
                                }
                                EscapeState::SawTilde => {
                                    match byte {
                                        b'.' => {
                                            should_disconnect = true;
                                            break;
                                        }
                                        b'?' => {
                                            let help = "\r\nSupported escape sequences:\r\n  ~.  Disconnect\r\n  ~?  Show this help\r\n  ~~  Send literal ~\r\n";
                                            let mut stderr = tokio::io::stderr();
                                            stderr.write_all(help.as_bytes()).await?;
                                            stderr.flush().await?;
                                            escape = EscapeState::Normal;
                                        }
                                        b'~' => {
                                            send_buf.push(b'~');
                                            escape = EscapeState::Normal;
                                        }
                                        _ => {
                                            send_buf.push(b'~');
                                            send_buf.push(byte);
                                            if byte == b'\r' || byte == b'\n' {
                                                escape = EscapeState::AfterNewline;
                                            } else {
                                                escape = EscapeState::Normal;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        if should_disconnect {
                            eprintln!("\r\nConnection to remote closed.");
                            data_send.finish().ok();
                            break;
                        }

                        if !send_buf.is_empty() {
                            data_send.write_all(&send_buf).await
                                .map_err(|e| format!("connection lost: {e}"))?;
                        }
                    }
                    None => {
                        data_send.finish().ok();
                    }
                }
            }

            // Window resize → control stream
            winch = winch_rx.recv() => {
                if let Some((cols, rows)) = winch {
                    let msg = ShellControlMsg::WindowChange { cols, rows };
                    ctrl_send.write_all(&msg.encode()).await
                        .map_err(|e| format!("control stream: {e}"))?;
                }
            }
        }
    }

    Ok(exit_code)
}

fn parse_destination(dest: &str) -> Result<(Option<String>, String), Box<dyn std::error::Error>> {
    if let Some(at_pos) = dest.find('@') {
        let user = &dest[..at_pos];
        let host = &dest[at_pos + 1..];
        Ok((Some(user.to_string()), host.to_string()))
    } else {
        Ok((None, dest.to_string()))
    }
}

fn term_size() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 {
            (ws.ws_col, ws.ws_row)
        } else {
            (80, 24)
        }
    }
}

fn set_raw_mode() -> Result<nix::sys::termios::Termios, Box<dyn std::error::Error>> {
    use nix::sys::termios;
    use std::os::fd::BorrowedFd;

    let stdin_fd = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
    let orig = termios::tcgetattr(stdin_fd)?;

    let mut raw = orig.clone();
    termios::cfmakeraw(&mut raw);
    termios::tcsetattr(stdin_fd, termios::SetArg::TCSANOW, &raw)?;

    Ok(orig)
}

fn restore_terminal(orig: &nix::sys::termios::Termios) {
    use nix::sys::termios;
    use std::os::fd::BorrowedFd;

    let stdin_fd = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
    let _ = termios::tcsetattr(stdin_fd, termios::SetArg::TCSANOW, orig);
}
