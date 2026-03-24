use std::path::PathBuf;

use clap::Parser;
use sqssh_core::keys;

#[derive(Parser)]
#[command(name = "sqssh-keygen", about = "Generate sqssh Ed25519 keypairs")]
struct Cli {
    /// Output file path for the private key (public key gets .pub suffix)
    #[arg(short = 'f', long = "file")]
    file: Option<PathBuf>,

    /// Comment for the public key
    #[arg(short = 'C', long = "comment", default_value = "")]
    comment: String,

    /// Show the public key fingerprint of a key file
    #[arg(long = "fingerprint")]
    fingerprint: Option<PathBuf>,

    /// Import an OpenSSH Ed25519 private key
    #[arg(long = "import-openssh")]
    import_openssh: Option<PathBuf>,

    /// Change the passphrase of an existing key
    #[arg(long = "change-passphrase")]
    change_passphrase: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    if let Some(ref path) = cli.fingerprint {
        match show_fingerprint(path) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(ref path) = cli.change_passphrase {
        match change_passphrase(path) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    if let Some(ref path) = cli.import_openssh {
        match import_openssh(path, &cli) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    match generate_key(&cli) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn generate_key(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let sqssh_dir = keys::ensure_sqssh_dir()?;

    let priv_path = cli
        .file
        .clone()
        .unwrap_or_else(|| sqssh_dir.join("id_ed25519"));
    let pub_path = priv_path.with_extension("pub");

    if priv_path.exists() {
        eprintln!(
            "{} already exists. Overwrite? (y/n) ",
            priv_path.display()
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("aborted.");
            std::process::exit(1);
        }
    }

    let (signing_key, verifying_key) = keys::generate_keypair();

    let comment = if cli.comment.is_empty() {
        format!(
            "{}@{}",
            whoami::username(),
            whoami::fallible::hostname().unwrap_or_else(|_| "unknown".into())
        )
    } else {
        cli.comment.clone()
    };

    // Prompt for passphrase
    let passphrase = keys::prompt_passphrase("Enter passphrase (empty for no passphrase): ")?;
    if !passphrase.is_empty() {
        let confirm = keys::prompt_passphrase("Enter same passphrase again: ")?;
        if *passphrase != *confirm {
            return Err("passphrases do not match".into());
        }
    }

    let pp = if passphrase.is_empty() {
        None
    } else {
        Some(passphrase.as_str())
    };
    keys::save_private_key_with_passphrase(&priv_path, &signing_key, pp)?;
    keys::save_public_key(&pub_path, &verifying_key, &comment)?;

    let encoded = keys::encode_pubkey(&verifying_key);
    eprintln!("Generated Ed25519 keypair:");
    eprintln!("  Private key: {}", priv_path.display());
    eprintln!("  Public key:  {}", pub_path.display());
    eprintln!("  Public key:  {encoded}");

    Ok(())
}

fn show_fingerprint(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Try loading as public key first, then as private key
    let verifying_key = if let Ok((key, _)) = keys::load_public_key(path) {
        key
    } else {
        let signing_key = keys::load_private_key(path)?;
        signing_key.verifying_key()
    };

    let encoded = keys::encode_pubkey(&verifying_key);
    println!("{encoded}");

    Ok(())
}

fn change_passphrase(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Load key (prompts for old passphrase if encrypted)
    let signing_key = keys::load_private_key(path)?;

    // Prompt for new passphrase
    let new_passphrase = keys::prompt_passphrase("Enter new passphrase (empty to remove encryption): ")?;
    if !new_passphrase.is_empty() {
        let confirm = keys::prompt_passphrase("Enter same passphrase again: ")?;
        if *new_passphrase != *confirm {
            return Err("passphrases do not match".into());
        }
    }

    let pp = if new_passphrase.is_empty() {
        None
    } else {
        Some(new_passphrase.as_str())
    };

    keys::save_private_key_with_passphrase(path, &signing_key, pp)?;

    if new_passphrase.is_empty() {
        eprintln!("Passphrase removed from {}", path.display());
    } else {
        eprintln!("Passphrase changed for {}", path.display());
    }

    Ok(())
}

fn import_openssh(
    _path: &PathBuf,
    _cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Parse OpenSSH Ed25519 private key format and extract the 32-byte seed
    eprintln!("OpenSSH import is not yet implemented");
    std::process::exit(1);
}
