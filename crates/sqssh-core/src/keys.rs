use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const PRIVATE_KEY_HEADER: &str = "SQSSH-ED25519-PRIVATE-KEY";
const PUBLIC_KEY_PREFIX: &str = "sqssh-ed25519";

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
pub fn encode_private_key(key: &SigningKey) -> Zeroizing<String> {
    Zeroizing::new(bs58::encode(key.to_bytes()).into_string())
}

/// Decode a base58-encoded private key seed.
pub fn decode_private_key(s: &str) -> Result<SigningKey> {
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
pub fn save_private_key(path: &Path, key: &SigningKey) -> Result<()> {
    let encoded = encode_private_key(key);
    let content = Zeroizing::new(format!("{PRIVATE_KEY_HEADER}\n{}\n", encoded.as_str()));
    fs::write(path, content.as_bytes())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
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
pub fn load_private_key(path: &Path) -> Result<SigningKey> {
    let content = Zeroizing::new(fs::read_to_string(path)?);
    let mut lines = content.lines();

    let header = lines
        .next()
        .ok_or_else(|| Error::InvalidKeyFormat("empty key file".into()))?;
    if header != PRIVATE_KEY_HEADER {
        return Err(Error::InvalidKeyFormat(format!(
            "expected header '{PRIVATE_KEY_HEADER}', got '{header}'"
        )));
    }

    let seed_line = lines
        .next()
        .ok_or_else(|| Error::InvalidKeyFormat("missing key data".into()))?
        .trim();

    decode_private_key(seed_line)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
