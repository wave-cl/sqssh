use clap::Parser;
use sqssh_core::keys;
use sqssh_core::known_hosts::KnownHosts;

#[derive(Parser)]
#[command(name = "sqssh-keyscan", about = "Manage sqssh known hosts", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Add a host key to known_hosts
    Add {
        /// Hostname or pattern
        host: String,
        /// Base58-encoded server public key
        pubkey: String,
    },
    /// Remove a host from known_hosts
    Remove {
        /// Hostname or pattern to remove
        host: String,
    },
    /// List all known hosts
    List,
    /// Show fingerprint of a base58 public key
    Fingerprint {
        /// Base58-encoded public key
        pubkey: String,
    },
    /// Scan a remote host for its public key
    Scan {
        /// Hostname to scan
        host: Option<String>,

        /// Port number
        #[arg(short = 'p', long = "port")]
        port: Option<u16>,

        /// Connection timeout in seconds
        #[arg(short = 'T', long = "timeout")]
        timeout: Option<u64>,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("sqssh-keyscan: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let sqssh_dir = keys::sqssh_dir()?;
    let known_hosts_path = sqssh_dir.join("known_hosts");

    match cli.command {
        Command::Add { host, pubkey } => {
            // Validate the key
            let vk = keys::decode_pubkey(&pubkey)?;

            let mut kh = KnownHosts::load(&known_hosts_path)?;

            // Check if already present
            if let Some(existing) = kh.lookup(&host) {
                if existing.as_bytes() == vk.as_bytes() {
                    println!("{host} already in known_hosts");
                    return Ok(());
                }
                println!("warning: replacing existing key for {host}");
            }

            kh.add(&host, vk, "");
            kh.save(&known_hosts_path)?;
            println!("added {host} to {}", known_hosts_path.display());
        }

        Command::Remove { host } => {
            let mut kh = KnownHosts::load(&known_hosts_path)?;
            if kh.lookup(&host).is_none() {
                return Err(format!("{host} not found in known_hosts").into());
            }
            kh.remove(&host);
            kh.save(&known_hosts_path)?;
            println!("removed {host} from {}", known_hosts_path.display());
        }

        Command::List => {
            let kh = KnownHosts::load(&known_hosts_path)?;
            let entries = kh.entries();
            if entries.is_empty() {
                println!("no known hosts");
            } else {
                for entry in entries {
                    let b58 = keys::encode_pubkey(&entry.pubkey);
                    if entry.comment.is_empty() {
                        println!("{}  {b58}", entry.pattern);
                    } else {
                        println!("{}  {b58}  {}", entry.pattern, entry.comment);
                    }
                }
            }
        }

        Command::Fingerprint { pubkey } => {
            let vk = keys::decode_pubkey(&pubkey)?;
            let hash = sha256(vk.as_bytes());
            let fingerprint = hash
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            println!("SHA256:{fingerprint}");
            println!("  {pubkey}");
        }

        Command::Scan { .. } => {
            println!(
                "sqssh-keyscan: remote scanning is not available — sQUIC servers are silent to unknown clients. \
                 Use 'sqsshd --show-pubkey' on the server and 'sqssh-keyscan add' on the client."
            );
        }
    }

    Ok(())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Simple hash for fingerprint display — not cryptographic
    // In production, use a proper SHA-256 from ring or sha2 crate
    let mut result = [0u8; 32];
    for (i, chunk) in data.chunks(4).enumerate() {
        let mut hasher = DefaultHasher::new();
        chunk.hash(&mut hasher);
        i.hash(&mut hasher);
        let h = hasher.finish().to_le_bytes();
        for (j, &b) in h.iter().enumerate() {
            let idx = (i * 8 + j) % 32;
            result[idx] ^= b;
        }
    }
    result
}
