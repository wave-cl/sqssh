use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;

use crate::error::{Error, Result};
use crate::keys::parse_public_key_line;

/// Maximum authorized_keys file size (64 KB).
const MAX_AUTHORIZED_KEYS_SIZE: u64 = 64 * 1024;

/// Maximum number of keys per user.
const MAX_KEYS_PER_USER: usize = 64;

/// Server authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Client must be in squic whitelist AND mapped to a user in authorized_keys.
    WhitelistAndUser,
    /// Any whitelisted client gets a default user. No Layer 2 needed.
    WhitelistOnly,
    /// Whitelist disabled. Any client with server pubkey can connect, but must have
    /// pubkey in authorized_keys.
    OpenAndUser,
}

/// Maps Ed25519 public keys to usernames (loaded from authorized_keys files).
#[derive(Debug, Default)]
pub struct AuthorizedKeys {
    entries: HashMap<[u8; 32], Vec<AuthorizedEntry>>,
}

#[derive(Debug, Clone)]
pub struct AuthorizedEntry {
    pub username: String,
    pub comment: String,
}

/// Safely read an authorized_keys file with security checks.
///
/// - Rejects symlinks (prevents a user from pointing at arbitrary files)
/// - Rejects files larger than MAX_AUTHORIZED_KEYS_SIZE
/// - Rejects files not owned by the expected user or root
fn safe_read_authorized_keys(path: &Path, expected_uid: Option<u32>) -> Result<String> {
    use std::os::unix::fs::MetadataExt;

    // Use symlink_metadata to detect symlinks without following them
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e.into()),
    };

    // Reject symlinks
    if meta.file_type().is_symlink() {
        tracing::warn!("rejecting symlinked authorized_keys: {}", path.display());
        return Err(Error::Auth(format!(
            "authorized_keys must not be a symlink: {}",
            path.display()
        )));
    }

    // Reject files that are too large
    if meta.len() > MAX_AUTHORIZED_KEYS_SIZE {
        tracing::warn!(
            "rejecting oversized authorized_keys ({} bytes): {}",
            meta.len(),
            path.display()
        );
        return Err(Error::Auth(format!(
            "authorized_keys too large ({} bytes, max {})",
            meta.len(),
            MAX_AUTHORIZED_KEYS_SIZE
        )));
    }

    // Check ownership: must be owned by the expected user or root
    if let Some(uid) = expected_uid {
        let file_uid = meta.uid();
        if file_uid != uid && file_uid != 0 {
            tracing::warn!(
                "rejecting authorized_keys owned by uid {} (expected {} or 0): {}",
                file_uid,
                uid,
                path.display()
            );
            return Err(Error::Auth(format!(
                "authorized_keys must be owned by the user or root: {}",
                path.display()
            )));
        }

        // Reject world-writable files
        let mode = meta.mode();
        if mode & 0o002 != 0 {
            tracing::warn!(
                "rejecting world-writable authorized_keys: {}",
                path.display()
            );
            return Err(Error::Auth(format!(
                "authorized_keys must not be world-writable: {}",
                path.display()
            )));
        }
    }

    Ok(fs::read_to_string(path)?)
}

impl AuthorizedKeys {
    /// Load authorized_keys from a file with safety checks.
    pub fn load_file(path: &Path, expected_uid: Option<u32>) -> Result<Vec<(VerifyingKey, String)>> {
        let content = safe_read_authorized_keys(path, expected_uid)?;
        if content.is_empty() {
            return Ok(Vec::new());
        }

        let mut keys = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if keys.len() >= MAX_KEYS_PER_USER {
                tracing::warn!(
                    "authorized_keys exceeds {} key limit, ignoring remaining: {}",
                    MAX_KEYS_PER_USER,
                    path.display()
                );
                break;
            }
            match parse_public_key_line(line) {
                Ok((key, comment)) => keys.push((key, comment)),
                Err(e) => tracing::warn!("skipping invalid authorized_keys entry: {e}"),
            }
        }

        Ok(keys)
    }

    /// Scan all system users and load their authorized_keys files.
    /// `ak_relative` is the path relative to each user's home dir (e.g. ".sqssh/authorized_keys").
    pub fn load_all_users(ak_relative: &str) -> Result<Self> {
        let mut ak = Self::default();

        // Reject ak_relative paths that try to escape (e.g. "../../etc/passwd")
        if ak_relative.contains("..") {
            return Err(Error::Auth(
                "authorized_keys_file must not contain '..'".into(),
            ));
        }

        let passwd = fs::read_to_string("/etc/passwd")?;
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 6 {
                continue;
            }
            let username = fields[0];
            let uid: u32 = match fields[2].parse() {
                Ok(u) => u,
                Err(_) => continue,
            };
            let home = fields[5];
            if home.is_empty() || home == "/nonexistent" || home == "/dev/null" {
                continue;
            }

            // Ensure home dir is absolute
            if !home.starts_with('/') {
                continue;
            }

            let ak_path = PathBuf::from(home).join(ak_relative);
            match Self::load_file(&ak_path, Some(uid)) {
                Ok(keys) if !keys.is_empty() => {
                    tracing::info!(
                        "loaded {} authorized key(s) for user '{username}' from {ak_path:?}",
                        keys.len()
                    );
                    for (key, comment) in &keys {
                        let entry = AuthorizedEntry {
                            username: username.to_string(),
                            comment: comment.clone(),
                        };
                        ak.entries
                            .entry(*key.as_bytes())
                            .or_default()
                            .push(entry);
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!("skipping {ak_path:?}: {e}");
                }
            }
        }

        Ok(ak)
    }

    /// Reload keys for a single user. Removes old keys for that user first.
    pub fn reload_user(&mut self, username: &str, uid: u32, ak_path: &Path) -> Result<()> {
        // Remove all keys for this user
        for entries in self.entries.values_mut() {
            entries.retain(|e| e.username != username);
        }
        self.entries.retain(|_, entries| !entries.is_empty());

        let keys = Self::load_file(ak_path, Some(uid))?;
        if !keys.is_empty() {
            tracing::info!(
                "reloaded {} key(s) for user '{username}'",
                keys.len()
            );
            for (key, comment) in &keys {
                let entry = AuthorizedEntry {
                    username: username.to_string(),
                    comment: comment.clone(),
                };
                self.entries
                    .entry(*key.as_bytes())
                    .or_default()
                    .push(entry);
            }
        }
        Ok(())
    }

    /// Check if a public key is authorized for a given username.
    pub fn is_authorized(&self, pubkey: &VerifyingKey, username: &str) -> bool {
        self.entries
            .get(pubkey.as_bytes())
            .map(|entries| entries.iter().any(|e| e.username == username))
            .unwrap_or(false)
    }

    /// Get all unique public keys (for building the squic whitelist).
    pub fn all_pubkeys(&self) -> Vec<[u8; 32]> {
        self.entries.keys().copied().collect()
    }

}
