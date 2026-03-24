use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use sqssh_core::keys;
use sqssh_core::protocol::{self, ChannelMsg, ChannelType, ControlMsg, DEFAULT_PORT};
use sqssh_core::stream::{Channel, ControlChannel};

mod pty_handler;

#[derive(Parser)]
#[command(name = "sqsshd", about = "sqssh server daemon")]
struct Cli {
    /// Listen address
    #[arg(short = 'l', long, default_value = "0.0.0.0")]
    listen: String,

    /// Listen port (UDP)
    #[arg(short = 'p', long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// Host key file
    #[arg(short = 'k', long = "host-key")]
    host_key: Option<PathBuf>,

    /// Show the server's public key and exit
    #[arg(long = "show-pubkey")]
    show_pubkey: bool,
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
    let host_key_path = cli
        .host_key
        .unwrap_or_else(|| PathBuf::from("/etc/sqssh/host_key"));

    let signing_key = keys::load_private_key(&host_key_path)?;
    let verifying_key = signing_key.verifying_key();

    if cli.show_pubkey {
        println!("{}", keys::encode_pubkey(&verifying_key));
        return Ok(());
    }

    let addr: SocketAddr = format!("{}:{}", cli.listen, cli.port).parse()?;

    let config = squic::Config {
        alpn_protocols: vec![protocol::ALPN.to_vec()],
        keep_alive: Some(std::time::Duration::from_secs(15)),
        ..Default::default()
    };

    let listener = squic::listen(addr, &signing_key, config).await?;
    let local_addr = listener.local_addr()?;
    eprintln!("sqsshd listening on {local_addr} (UDP)");
    eprintln!("server pubkey: {}", keys::encode_pubkey(&verifying_key));

    loop {
        let incoming = match listener.accept().await {
            Some(incoming) => incoming,
            None => break,
        };

        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming).await {
                tracing::error!("connection error: {e}");
            }
        });
    }

    Ok(())
}

async fn handle_connection(incoming: quinn::Incoming) -> Result<(), Box<dyn std::error::Error>> {
    let conn = incoming.await?;
    let remote = conn.remote_address();
    tracing::info!("new connection from {remote}");

    // Accept control channel (stream 0)
    let mut control = ControlChannel::accept(&conn).await?;

    // Phase 1: No user auth — just accept the connection
    let auth_msg = control.recv().await?;
    let username = match auth_msg {
        ControlMsg::AuthRequest { username, .. } => {
            tracing::info!("auth request from user '{username}'");
            username
        }
        other => {
            tracing::warn!("expected AuthRequest, got {other:?}");
            return Ok(());
        }
    };

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
                tokio::spawn(async move {
                    if let Err(e) = handle_session(channel, &user).await {
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
    _username: &str,
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
                let output = tokio::process::Command::new("/bin/sh")
                    .arg("-c")
                    .arg(&command)
                    .output()
                    .await?;

                channel
                    .send(&ChannelMsg::Data {
                        payload: output.stdout,
                    })
                    .await?;

                if !output.stderr.is_empty() {
                    channel
                        .send(&ChannelMsg::ExtendedData {
                            data_type: 1,
                            payload: output.stderr,
                        })
                        .await?;
                }

                let code = output.status.code().unwrap_or(1) as u32;
                channel.send(&ChannelMsg::ExitStatus { code }).await?;
                channel.send(&ChannelMsg::Eof).await?;
                channel.send(&ChannelMsg::Close).await?;
                return Ok(());
            }
            other => {
                tracing::debug!("ignoring pre-shell message: {other:?}");
            }
        }
    }

    // Spawn shell with PTY
    pty_handler::run_shell(&mut channel, &term, cols, rows).await
}
