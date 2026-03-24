use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const PRIVATE_KEY_HEADER: &str = "SQSSH-ED25519-PRIVATE-KEY";
const ENCRYPTED_KEY_HEADER: &str = "SQSSH-ED25519-ENCRYPTED-KEY";
const PUBLIC_KEY_PREFIX: &str = "sqssh-ed25519";

/// Encrypted key blob serialized as msgpack.
#[derive(Serialize, Deserialize)]
struct EncryptedKeyBlob {
    /// Argon2 memory cost in KiB
    m_cost: u32,
    /// Argon2 time cost (iterations)
    t_cost: u32,
    /// Argon2 parallelism
    p_cost: u32,
    /// Random salt (16 bytes)
    salt: Vec<u8>,
    /// ChaCha20-Poly1305 nonce (12 bytes)
    nonce: Vec<u8>,
    /// Encrypted seed + poly1305 tag (48 bytes)
    ciphertext: Vec<u8>,
}

/// Generate a new Ed25519 keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Encode a public key as base58.
pub fn encode_pubkey(key: &VerifyingKey) -> String {
    bs58::encode(key.as_bytes()).into_string()
}

/// Decode a base58-encoded public key.
pub fn decode_pubkey(s: &str) -> Result<VerifyingKey> {
    let bytes = bs58::decode(s).into_vec()?;
    if bytes.len() != 32 {
        return Err(Error::InvalidKeyFormat(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| Error::InvalidKeyFormat(format!("invalid Ed25519 public key: {e}")))
}

/// Encode a private key seed as base58.
fn encode_private_key(key: &SigningKey) -> Zeroizing<String> {
    Zeroizing::new(bs58::encode(key.to_bytes()).into_string())
}

/// Decode a base58-encoded private key seed.
fn decode_private_key(s: &str) -> Result<SigningKey> {
    let bytes = Zeroizing::new(bs58::decode(s).into_vec()?);
    if bytes.len() != 32 {
        return Err(Error::InvalidKeyFormat(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let key = SigningKey::from_bytes(&arr);
    arr.iter_mut().for_each(|b| *b = 0);
    Ok(key)
}

/// Save a private key to a file with mode 0600.
/// If passphrase is Some and non-empty, the key is encrypted.
pub fn save_private_key(path: &Path, key: &SigningKey) -> Result<()> {
    save_private_key_with_passphrase(path, key, None)
}

/// Save a private key, optionally encrypted with a passphrase.
pub fn save_private_key_with_passphrase(
    path: &Path,
    key: &SigningKey,
    passphrase: Option<&str>,
) -> Result<()> {
    let content = match passphrase {
        Some(pp) if !pp.is_empty() => {
            let encrypted = encrypt_seed(&key.to_bytes(), pp)?;
            Zeroizing::new(format!("{ENCRYPTED_KEY_HEADER}\n{encrypted}\n"))
        }
        _ => {
            let encoded = encode_private_key(key);
            Zeroizing::new(format!("{PRIVATE_KEY_HEADER}\n{}\n", encoded.as_str()))
        }
    };
    fs::write(path, content.as_bytes())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Encrypt a 32-byte seed with a passphrase using argon2id + chacha20-poly1305.
fn encrypt_seed(seed: &[u8; 32], passphrase: &str) -> Result<String> {
    use rand::RngCore;

    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Derive encryption key via argon2id
    let mut derived_key = Zeroizing::new([0u8; 32]);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| Error::Key(format!("argon2 params: {e}")))?,
    );
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, derived_key.as_mut())
        .map_err(|e| Error::Key(format!("argon2 hash: {e}")))?;

    // Encrypt with chacha20-poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(derived_key.as_ref())
        .map_err(|e| Error::Key(format!("cipher init: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, seed.as_ref())
        .map_err(|e| Error::Key(format!("encrypt: {e}")))?;

    let blob = EncryptedKeyBlob {
        m_cost: 65536,
        t_cost: 3,
        p_cost: 4,
        salt: salt.to_vec(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    };

    let encoded = rmp_serde::to_vec(&blob)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    Ok(bs58::encode(encoded).into_string())
}

/// Decrypt an encrypted key blob with a passphrase.
fn decrypt_seed(encrypted_b58: &str, passphrase: &str) -> Result<SigningKey> {
    let encoded = bs58::decode(encrypted_b58).into_vec()?;
    let blob: EncryptedKeyBlob = rmp_serde::from_slice(&encoded)
        .map_err(|e| Error::Serialization(e.to_string()))?;

    if blob.salt.len() != 16 || blob.nonce.len() != 12 {
        return Err(Error::InvalidKeyFormat("invalid encrypted key blob".into()));
    }

    // Derive key
    let mut derived_key = Zeroizing::new([0u8; 32]);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(blob.m_cost, blob.t_cost, blob.p_cost, Some(32))
            .map_err(|e| Error::Key(format!("argon2 params: {e}")))?,
    );
    argon2
        .hash_password_into(passphrase.as_bytes(), &blob.salt, derived_key.as_mut())
        .map_err(|e| Error::Key(format!("argon2 hash: {e}")))?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(derived_key.as_ref())
        .map_err(|e| Error::Key(format!("cipher init: {e}")))?;
    let nonce = Nonce::from_slice(&blob.nonce);
    let seed = cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|_| Error::Key("decryption failed (wrong passphrase?)".into()))?;

    if seed.len() != 32 {
        return Err(Error::InvalidKeyFormat("decrypted seed is not 32 bytes".into()));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&seed);
    let key = SigningKey::from_bytes(&arr);
    arr.iter_mut().for_each(|b| *b = 0);
    Ok(key)
}

/// Prompt for a passphrase with echo disabled.
/// Falls back to plain read if stdin is not a terminal.
pub fn prompt_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::{self, BufRead, Write};

    eprint!("{prompt}");
    io::stderr().flush().ok();

    let stdin_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
    let is_tty = unsafe { libc::isatty(libc::STDIN_FILENO) } == 1;

    let orig = if is_tty {
        let orig = nix::sys::termios::tcgetattr(stdin_fd).ok();
        if let Some(ref o) = orig {
            let mut noecho = o.clone();
            noecho.local_flags.remove(nix::sys::termios::LocalFlags::ECHO);
            nix::sys::termios::tcsetattr(stdin_fd, nix::sys::termios::SetArg::TCSANOW, &noecho).ok();
        }
        orig
    } else {
        None
    };

    let mut line = String::new();
    let result = io::stdin().lock().read_line(&mut line);

    // Restore echo
    if let Some(ref o) = orig {
        nix::sys::termios::tcsetattr(stdin_fd, nix::sys::termios::SetArg::TCSANOW, o).ok();
        eprintln!(); // newline after hidden input
    }

    result.map_err(|e| Error::Key(format!("read passphrase: {e}")))?;
    Ok(Zeroizing::new(line.trim_end().to_string()))
}

/// Save a public key to a file.
pub fn save_public_key(path: &Path, key: &VerifyingKey, comment: &str) -> Result<()> {
    let encoded = encode_pubkey(key);
    let content = format!("{PUBLIC_KEY_PREFIX} {encoded} {comment}\n");
    fs::write(path, content.as_bytes())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

/// Load a private key from a file.
/// If the key is encrypted, prompts for passphrase interactively.
pub fn load_private_key(path: &Path) -> Result<SigningKey> {
    let content = Zeroizing::new(fs::read_to_string(path)?);
    let mut lines = content.lines();

    let header = lines
        .next()
        .ok_or_else(|| Error::InvalidKeyFormat("empty key file".into()))?;

    let data_line = lines
        .next()
        .ok_or_else(|| Error::InvalidKeyFormat("missing key data".into()))?
        .trim();

    if header == ENCRYPTED_KEY_HEADER {
        let passphrase = prompt_passphrase(&format!(
            "Enter passphrase for {}: ",
            path.display()
        ))?;
        decrypt_seed(data_line, &passphrase)
    } else if header == PRIVATE_KEY_HEADER {
        decode_private_key(data_line)
    } else {
        Err(Error::InvalidKeyFormat(format!(
            "unknown key header: '{header}'"
        )))
    }
}

/// Load a private key with an explicit passphrase (no interactive prompt).
pub fn load_private_key_with_passphrase(path: &Path, passphrase: &str) -> Result<SigningKey> {
    let content = Zeroizing::new(fs::read_to_string(path)?);
    let mut lines = content.lines();

    let header = lines
        .next()
        .ok_or_else(|| Error::InvalidKeyFormat("empty key file".into()))?;

    let data_line = lines
        .next()
        .ok_or_else(|| Error::InvalidKeyFormat("missing key data".into()))?
        .trim();

    if header == ENCRYPTED_KEY_HEADER {
        decrypt_seed(data_line, passphrase)
    } else if header == PRIVATE_KEY_HEADER {
        decode_private_key(data_line)
    } else {
        Err(Error::InvalidKeyFormat(format!(
            "unknown key header: '{header}'"
        )))
    }
}

/// Load a public key from a file.
pub fn load_public_key(path: &Path) -> Result<(VerifyingKey, String)> {
    let content = fs::read_to_string(path)?;
    parse_public_key_line(content.lines().next().unwrap_or(""))
}

/// Parse a single public key line: "sqssh-ed25519 <base58-pubkey> [comment]"
pub fn parse_public_key_line(line: &str) -> Result<(VerifyingKey, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Err(Error::InvalidKeyFormat("empty or comment line".into()));
    }

    let mut parts = line.splitn(3, ' ');
    let prefix = parts
        .next()
        .ok_or_else(|| Error::InvalidKeyFormat("missing key type".into()))?;
    if prefix != PUBLIC_KEY_PREFIX {
        return Err(Error::InvalidKeyFormat(format!(
            "expected '{PUBLIC_KEY_PREFIX}', got '{prefix}'"
        )));
    }

    let key_data = parts
        .next()
        .ok_or_else(|| Error::InvalidKeyFormat("missing key data".into()))?;
    let comment = parts.next().unwrap_or("").to_string();

    let key = decode_pubkey(key_data)?;
    Ok((key, comment))
}

/// Returns the default sqssh directory (~/.sqssh).
pub fn sqssh_dir() -> Result<std::path::PathBuf> {
    dirs::home_dir()
        .map(|h| h.join(".sqssh"))
        .ok_or_else(|| Error::Key("could not determine home directory".into()))
}

/// Ensure the ~/.sqssh directory exists with mode 0700.
pub fn ensure_sqssh_dir() -> Result<std::path::PathBuf> {
    let dir = sqssh_dir()?;
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// Load the key_map file (~/.sqssh/key_map).
/// Returns a map of hostname → key name (relative to ~/.sqssh/).
fn load_key_map() -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;

    let mut map = HashMap::new();
    let path = match sqssh_dir() {
        Ok(d) => d.join("key_map"),
        Err(_) => return map,
    };

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return map,
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        if let (Some(host), Some(key_name)) = (parts.next(), parts.next()) {
            map.insert(host.to_string(), key_name.trim().to_string());
        }
    }

    map
}

/// Save a host → key mapping to ~/.sqssh/key_map.
pub fn save_key_mapping(host: &str, key_name: &str) -> Result<()> {
    let dir = sqssh_dir()?;
    let path = dir.join("key_map");

    let mut map = load_key_map();
    map.insert(host.to_string(), key_name.to_string());

    let mut content = String::new();
    for (h, k) in &map {
        content.push_str(&format!("{h} {k}\n"));
    }
    fs::write(&path, content)?;
    Ok(())
}

/// Look up which key to use for a host from the key_map.
pub fn key_for_host(host: &str) -> Option<std::path::PathBuf> {
    let map = load_key_map();
    let key_name = map.get(host)?;
    let dir = sqssh_dir().ok()?;
    let path = dir.join(key_name);
    if path.exists() {
        Some(path)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_roundtrip() {
        let (signing, verifying) = generate_keypair();
        let encoded = encode_pubkey(&verifying);
        let decoded = decode_pubkey(&encoded).unwrap();
        assert_eq!(verifying, decoded);

        let priv_encoded = encode_private_key(&signing);
        let priv_decoded = decode_private_key(&priv_encoded).unwrap();
        assert_eq!(signing.to_bytes(), priv_decoded.to_bytes());
    }

    #[test]
    fn test_save_load_keys() {
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("id_ed25519");
        let pub_path = dir.path().join("id_ed25519.pub");

        let (signing, verifying) = generate_keypair();
        save_private_key(&priv_path, &signing).unwrap();
        save_public_key(&pub_path, &verifying, "test@host").unwrap();

        let loaded_signing = load_private_key(&priv_path).unwrap();
        assert_eq!(signing.to_bytes(), loaded_signing.to_bytes());

        let (loaded_verifying, comment) = load_public_key(&pub_path).unwrap();
        assert_eq!(verifying, loaded_verifying);
        assert_eq!(comment, "test@host");
    }

    #[test]
    fn test_parse_public_key_line() {
        let (_, verifying) = generate_keypair();
        let encoded = encode_pubkey(&verifying);
        let line = format!("sqssh-ed25519 {encoded} alice@laptop");

        let (parsed_key, comment) = parse_public_key_line(&line).unwrap();
        assert_eq!(verifying, parsed_key);
        assert_eq!(comment, "alice@laptop");
    }

    #[test]
    fn test_comment_line_skipped() {
        assert!(parse_public_key_line("# this is a comment").is_err());
        assert!(parse_public_key_line("").is_err());
    }
}
