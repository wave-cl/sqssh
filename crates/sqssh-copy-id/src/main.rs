use std::path::PathBuf;

use clap::Parser;
use sqssh_core::client;
use sqssh_core::keys;
use sqssh_core::protocol;

#[derive(Parser)]
#[command(name = "sqssh-copy-id", about = "Deploy public key to remote host")]
struct Cli {
    /// [user@]hostname
    destination: String,

    /// Public key file to deploy
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Port (UDP)
    #[arg(short = 'p', long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("sqssh-copy-id: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Parse destination
    let (user, host) = if let Some(at) = cli.destination.find('@') {
        (
            Some(cli.destination[..at].to_string()),
            cli.destination[at + 1..].to_string(),
        )
    } else {
        (None, cli.destination.clone())
    };

    // Load the public key to deploy
    let sqssh_dir = keys::sqssh_dir()?;
    let pub_key_path = cli
        .identity
        .unwrap_or_else(|| sqssh_dir.join("id_ed25519.pub"));

    let (verifying_key, comment) = keys::load_public_key(&pub_key_path)?;
    let pubkey_b58 = keys::encode_pubkey(&verifying_key);
    let key_line = format!("sqssh-ed25519 {pubkey_b58} {comment}");

    eprintln!("deploying key: {pubkey_b58}");

    // Connect to remote
    let conn = client::connect(
        &host,
        user.as_deref(),
        cli.port,
        None,
    )
    .await?;

    // Build remote command
    let cmd = format!(
        "mkdir -p ~/.sqssh && \
         chmod 700 ~/.sqssh && \
         grep -qF '{pubkey_b58}' ~/.sqssh/authorized_keys 2>/dev/null && \
         echo 'KEY_EXISTS' || \
         (echo '{key_line}' >> ~/.sqssh/authorized_keys && \
         chmod 600 ~/.sqssh/authorized_keys && \
         sqsshctl reload-keys 2>/dev/null; \
         echo 'KEY_ADDED')"
    );

    // Open raw exec bidi stream: [RAW_EXEC][2 bytes cmd_len][command]
    let (mut send, mut recv) = conn.conn.open_bi().await?;
    let cmd_bytes = cmd.as_bytes();
    let mut header = Vec::with_capacity(1 + 2 + cmd_bytes.len());
    header.push(protocol::RAW_EXEC);
    header.extend_from_slice(&(cmd_bytes.len() as u16).to_be_bytes());
    header.extend_from_slice(cmd_bytes);
    send.write_all(&header).await
        .map_err(|e| format!("write exec header: {e}"))?;
    send.finish()
        .map_err(|e| format!("finish: {e}"))?;

    // Read all response data (stdout + 4-byte exit code at the end)
    let mut all_data = Vec::new();
    let mut buf = vec![0u8; 8192];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => all_data.extend_from_slice(&buf[..n]),
            Ok(None) => break,
            Err(e) => return Err(format!("read error: {e}").into()),
        }
    }

    // Extract exit code from last 4 bytes, rest is stdout
    let (stdout, exit_code) = if all_data.len() >= 4 {
        let off = all_data.len() - 4;
        let code = u32::from_be_bytes([all_data[off], all_data[off + 1], all_data[off + 2], all_data[off + 3]]);
        (all_data[..off].to_vec(), code)
    } else {
        (all_data, 0u32)
    };

    let output = String::from_utf8_lossy(&stdout).trim().to_string();

    if output.contains("KEY_EXISTS") {
        eprintln!("key already present on {host}");
        // Save key mapping even if already present
        let key_name = pub_key_path
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "id_ed25519".into());
        keys::save_key_mapping(&host, &key_name).ok();
    } else if output.contains("KEY_ADDED") {
        eprintln!("key added to {host}:~/.sqssh/authorized_keys");
        // Auto-map this key for future connections
        let key_name = pub_key_path
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "id_ed25519".into());
        keys::save_key_mapping(&host, &key_name).ok();
    } else {
        eprintln!("unexpected output: {output}");
        if exit_code != 0 {
            std::process::exit(exit_code as i32);
        }
    }

    Ok(())
}
