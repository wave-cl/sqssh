use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use ed25519_dalek::SigningKey;
use sqssh_core::keys;
use sqssh_core::protocol::{
    AgentKeyEntry, AgentRequest, AgentResponse,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

#[derive(Parser)]
#[command(name = "sqssh-agent", about = "sqssh key agent")]
struct Cli {
    /// Run in foreground (debug mode)
    #[arg(short = 'd', long)]
    debug: bool,

    /// Socket path
    #[arg(short = 's', long)]
    socket: Option<PathBuf>,
}

struct AgentState {
    keys: RwLock<HashMap<[u8; 32], (SigningKey, String)>>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.debug {
        tracing_subscriber::fmt::init();
    }

    if let Err(e) = run(cli).await {
        eprintln!("sqssh-agent: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let sqssh_dir = keys::ensure_sqssh_dir()?;
    let socket_path = cli
        .socket
        .unwrap_or_else(|| sqssh_dir.join("agent.sock"));

    // Remove stale socket — only if it's actually a socket, not a symlink
    if let Ok(meta) = std::fs::symlink_metadata(&socket_path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "refusing to start: {} is a symlink",
                socket_path.display()
            )
            .into());
        }
        if meta.file_type().is_socket() {
            std::fs::remove_file(&socket_path)?;
        }
    }

    let listener = tokio::net::UnixListener::bind(&socket_path)?;

    // Set socket permissions to owner-only
    std::fs::set_permissions(
        &socket_path,
        std::fs::Permissions::from_mode(0o600),
    )?;

    // Print shell commands for eval (like ssh-agent)
    println!(
        "SQSSH_AGENT_SOCK={}; export SQSSH_AGENT_SOCK;",
        socket_path.display()
    );
    println!("echo Agent pid {};", std::process::id());

    if cli.debug {
        eprintln!("sqssh-agent listening on {}", socket_path.display());
    }

    let state = Arc::new(AgentState {
        keys: RwLock::new(HashMap::new()),
    });

    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, &state).await {
                tracing::debug!("agent client error: {e}");
            }
        });
    }
}

async fn handle_client(
    mut stream: tokio::net::UnixStream,
    state: &AgentState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read request (binary)
    let request = AgentRequest::decode_async(&mut stream).await?;
    let response = handle_request(request, state).await;

    // Send response (binary)
    let resp_data = response.encode();
    stream.write_all(&resp_data).await?;

    Ok(())
}

async fn handle_request(request: AgentRequest, state: &AgentState) -> AgentResponse {
    match request {
        AgentRequest::AddKey { seed, comment } => {
            if seed.len() != 32 {
                return AgentResponse::Error {
                    message: "seed must be 32 bytes".into(),
                };
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&seed);
            let signing_key = SigningKey::from_bytes(&arr);
            let pubkey = *signing_key.verifying_key().as_bytes();
            let pubkey_b58 = keys::encode_pubkey(&signing_key.verifying_key());

            state
                .keys
                .write()
                .await
                .insert(pubkey, (signing_key, comment));

            tracing::info!("added key: {pubkey_b58}");
            AgentResponse::Ok
        }

        AgentRequest::RemoveKey { pubkey } => {
            if pubkey.len() != 32 {
                return AgentResponse::Error {
                    message: "pubkey must be 32 bytes".into(),
                };
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pubkey);
            let mut keys = state.keys.write().await;
            if keys.remove(&arr).is_some() {
                tracing::info!("removed key");
                AgentResponse::Ok
            } else {
                AgentResponse::Error {
                    message: "key not found".into(),
                }
            }
        }

        AgentRequest::RemoveAll => {
            let mut keys = state.keys.write().await;
            let count = keys.len();
            keys.clear();
            tracing::info!("removed {count} key(s)");
            AgentResponse::Ok
        }

        AgentRequest::ListKeys => {
            let keys = state.keys.read().await;
            let entries = keys
                .iter()
                .map(|(pubkey, (_, comment))| AgentKeyEntry {
                    pubkey: pubkey.to_vec(),
                    comment: comment.clone(),
                })
                .collect();
            AgentResponse::Keys { entries }
        }

        AgentRequest::GetSeed { pubkey } => {
            if pubkey.len() != 32 {
                return AgentResponse::Error {
                    message: "pubkey must be 32 bytes".into(),
                };
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pubkey);
            let keys = state.keys.read().await;
            match keys.get(&arr) {
                Some((signing_key, _)) => AgentResponse::Seed {
                    seed: signing_key.to_bytes().to_vec(),
                },
                None => AgentResponse::Error {
                    message: "key not found".into(),
                },
            }
        }
    }
}
