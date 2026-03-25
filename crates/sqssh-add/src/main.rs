use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use clap::Parser;
use sqssh_core::keys;
use sqssh_core::protocol::{AgentRequest, AgentResponse};

#[derive(Parser)]
#[command(name = "sqssh-add", about = "Add keys to sqssh-agent")]
struct Cli {
    /// Key file(s) to add (default: ~/.sqssh/id_ed25519)
    keys: Vec<PathBuf>,

    /// List keys in agent
    #[arg(short = 'l', long)]
    list: bool,

    /// Remove a specific key
    #[arg(short = 'd', long)]
    delete: Option<PathBuf>,

    /// Remove all keys
    #[arg(short = 'D', long = "delete-all")]
    delete_all: bool,
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("sqssh-add: {e}");
        std::process::exit(1);
    }
}

fn agent_socket() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(path) = std::env::var("SQSSH_AGENT_SOCK") {
        return Ok(PathBuf::from(path));
    }
    let sqssh_dir = keys::sqssh_dir()?;
    Ok(sqssh_dir.join("agent.sock"))
}

fn send_request(
    request: &AgentRequest,
) -> Result<AgentResponse, Box<dyn std::error::Error>> {
    let socket_path = agent_socket()?;
    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| format!("could not connect to agent at {}: {e}", socket_path.display()))?;

    let data = request.encode();
    stream.write_all(&data)?;

    let response = AgentResponse::decode(&mut stream)?;
    Ok(response)
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    if cli.list {
        return list_keys();
    }

    if cli.delete_all {
        return remove_all();
    }

    if let Some(ref key_path) = cli.delete {
        return remove_key(key_path);
    }

    // Add keys
    let key_paths = if cli.keys.is_empty() {
        let sqssh_dir = keys::sqssh_dir()?;
        vec![sqssh_dir.join("id_ed25519")]
    } else {
        cli.keys
    };

    for path in &key_paths {
        add_key(path)?;
    }

    Ok(())
}

fn add_key(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = keys::load_private_key(path)?;
    let verifying_key = signing_key.verifying_key();
    let pubkey_b58 = keys::encode_pubkey(&verifying_key);

    // Try to load comment from .pub file
    let pub_path = PathBuf::from(format!("{}.pub", path.display()));
    let comment = if pub_path.exists() {
        keys::load_public_key(&pub_path)
            .map(|(_, c)| c)
            .unwrap_or_default()
    } else {
        String::new()
    };

    let response = send_request(&AgentRequest::AddKey {
        seed: signing_key.to_bytes().to_vec(),
        comment,
    })?;

    match response {
        AgentResponse::Ok => {
            eprintln!("Identity added: {} ({pubkey_b58})", path.display());
        }
        AgentResponse::Error { message } => {
            return Err(format!("failed to add key: {message}").into());
        }
        _ => {
            return Err("unexpected response".into());
        }
    }

    Ok(())
}

fn list_keys() -> Result<(), Box<dyn std::error::Error>> {
    let response = send_request(&AgentRequest::ListKeys)?;

    match response {
        AgentResponse::Keys { entries } => {
            if entries.is_empty() {
                eprintln!("The agent has no identities.");
            } else {
                for entry in &entries {
                    let pubkey_bytes: [u8; 32] = entry
                        .pubkey
                        .as_slice()
                        .try_into()
                        .map_err(|_| "invalid pubkey")?;
                    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_bytes)?;
                    let b58 = keys::encode_pubkey(&vk);
                    if entry.comment.is_empty() {
                        println!("{b58}");
                    } else {
                        println!("{b58} {}", entry.comment);
                    }
                }
                eprintln!("{} key(s) in agent", entries.len());
            }
        }
        AgentResponse::Error { message } => {
            return Err(message.into());
        }
        _ => {
            return Err("unexpected response".into());
        }
    }

    Ok(())
}

fn remove_key(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = keys::load_private_key(path)?;
    let pubkey = signing_key.verifying_key();

    let response = send_request(&AgentRequest::RemoveKey {
        pubkey: pubkey.as_bytes().to_vec(),
    })?;

    match response {
        AgentResponse::Ok => {
            eprintln!("Identity removed: {}", path.display());
        }
        AgentResponse::Error { message } => {
            return Err(format!("failed to remove key: {message}").into());
        }
        _ => {
            return Err("unexpected response".into());
        }
    }

    Ok(())
}

fn remove_all() -> Result<(), Box<dyn std::error::Error>> {
    let response = send_request(&AgentRequest::RemoveAll)?;

    match response {
        AgentResponse::Ok => {
            eprintln!("All identities removed.");
        }
        AgentResponse::Error { message } => {
            return Err(format!("failed: {message}").into());
        }
        _ => {
            return Err("unexpected response".into());
        }
    }

    Ok(())
}
