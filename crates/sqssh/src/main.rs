use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use clap::Parser;
use sqssh_core::config::ClientConfig;
use sqssh_core::keys;
use sqssh_core::known_hosts::KnownHosts;
use sqssh_core::protocol::{self, ChannelMsg, ChannelType, ControlMsg};
use sqssh_core::stream::{Channel, ControlChannel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

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
        .or(resolved.identity_file.map(PathBuf::from))
        .unwrap_or_else(|| sqssh_dir.join("id_ed25519"));
    let signing_key = keys::load_private_key(&identity_path)?;
    let verifying_key = signing_key.verifying_key();

    // Connect via squic
    let squic_config = squic::Config {
        alpn_protocols: vec![protocol::ALPN.to_vec()],
        keep_alive: Some(std::time::Duration::from_secs(resolved.keepalive_interval)),
        ..Default::default()
    };

    let conn = squic::dial(addr, server_pubkey.as_bytes(), squic_config).await?;

    // Open control channel and authenticate
    let mut control = ControlChannel::open(&conn).await?;
    control
        .send(&ControlMsg::AuthRequest {
            username: user.clone(),
            pubkey: verifying_key.as_bytes().to_vec(),
        })
        .await?;

    match control.recv().await? {
        ControlMsg::AuthSuccess => {}
        ControlMsg::AuthFailure { message } => {
            return Err(format!("authentication failed: {message}").into());
        }
        other => {
            return Err(format!("unexpected response: {other:?}").into());
        }
    }

    // Open a session channel
    let mut channel = Channel::open(&conn, ChannelType::Session).await?;

    // Wait for ChannelOpenConfirm
    match channel.recv().await? {
        ChannelMsg::ChannelOpenConfirm => {}
        ChannelMsg::ChannelOpenFailure { description, .. } => {
            return Err(format!("channel open failed: {description}").into());
        }
        other => {
            return Err(format!("unexpected: {other:?}").into());
        }
    }

    if cli.command.is_empty() {
        // Interactive shell
        run_interactive_shell(&mut channel).await
    } else {
        // Remote command
        let cmd = cli.command.join(" ");
        run_remote_command(&mut channel, &cmd).await
    }
}

async fn run_interactive_shell(
    channel: &mut Channel,
) -> Result<(), Box<dyn std::error::Error>> {
    // Get terminal size
    let (cols, rows) = term_size();
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into());

    // Request PTY
    channel
        .send(&ChannelMsg::PtyRequest {
            term,
            cols: cols as u32,
            rows: rows as u32,
        })
        .await?;

    match channel.recv().await? {
        ChannelMsg::PtySuccess => {}
        other => {
            return Err(format!("PTY request failed: {other:?}").into());
        }
    }

    // Request shell
    channel.send(&ChannelMsg::ShellRequest).await?;

    // Set local terminal to raw mode
    let orig_termios = set_raw_mode()?;

    let result = relay_stdio(channel).await;

    // Restore terminal
    restore_terminal(&orig_termios);

    result
}

async fn run_remote_command(
    channel: &mut Channel,
    command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    channel
        .send(&ChannelMsg::ExecRequest {
            command: command.to_string(),
        })
        .await?;

    let mut exit_code = 0u32;

    loop {
        match channel.recv().await? {
            ChannelMsg::Data { payload } => {
                let mut stdout = tokio::io::stdout();
                stdout.write_all(&payload).await?;
                stdout.flush().await?;
            }
            ChannelMsg::ExtendedData { payload, .. } => {
                let mut stderr = tokio::io::stderr();
                stderr.write_all(&payload).await?;
                stderr.flush().await?;
            }
            ChannelMsg::ExitStatus { code } => {
                exit_code = code;
            }
            ChannelMsg::Eof | ChannelMsg::Close => break,
            _ => {}
        }
    }

    if exit_code != 0 {
        std::process::exit(exit_code as i32);
    }
    Ok(())
}

async fn relay_stdio(channel: &mut Channel) -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = tokio::io::stdin();
    let mut stdin_buf = vec![0u8; 4096];
    let mut exit_code = 0u32;

    loop {
        tokio::select! {
            // stdin → channel
            n = stdin.read(&mut stdin_buf) => {
                let n = n?;
                if n == 0 {
                    channel.send(&ChannelMsg::Eof).await?;
                    continue;
                }
                channel.send(&ChannelMsg::Data {
                    payload: stdin_buf[..n].to_vec(),
                }).await?;
            }

            // channel → stdout
            msg = channel.recv() => {
                match msg? {
                    ChannelMsg::Data { payload } => {
                        let mut stdout = tokio::io::stdout();
                        stdout.write_all(&payload).await?;
                        stdout.flush().await?;
                    }
                    ChannelMsg::ExtendedData { payload, .. } => {
                        let mut stderr = tokio::io::stderr();
                        stderr.write_all(&payload).await?;
                        stderr.flush().await?;
                    }
                    ChannelMsg::ExitStatus { code } => {
                        exit_code = code;
                    }
                    ChannelMsg::Eof | ChannelMsg::Close => break,
                    ChannelMsg::WindowChange { .. } => {}
                    _ => {}
                }
            }
        }
    }

    if exit_code != 0 {
        std::process::exit(exit_code as i32);
    }
    Ok(())
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
