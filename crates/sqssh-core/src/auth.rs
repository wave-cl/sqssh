use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;

use crate::error::Result;
use crate::keys::parse_public_key_line;

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
    /// Maps base58-encoded pubkey to list of usernames it's authorized for.
    entries: HashMap<[u8; 32], Vec<AuthorizedEntry>>,
}

#[derive(Debug, Clone)]
pub struct AuthorizedEntry {
    pub username: String,
    pub comment: String,
}

impl AuthorizedKeys {
    /// Load authorized_keys from a file, returning (key, comment) pairs.
    pub fn load_file(path: &Path) -> Result<Vec<(VerifyingKey, String)>> {
        if !path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(path)?;
        let mut keys = Vec::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
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

        let passwd = fs::read_to_string("/etc/passwd")?;
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() < 6 {
                continue;
            }
            let username = fields[0];
            let home = fields[5];
            if home.is_empty() || home == "/nonexistent" || home == "/dev/null" {
                continue;
            }

            let ak_path = PathBuf::from(home).join(ak_relative);
            match Self::load_file(&ak_path) {
                Ok(keys) if !keys.is_empty() => {
                    tracing::info!(
                        "loaded {} authorized key(s) for user '{username}' from {ak_path:?}",
                        keys.len()
                    );
                    ak.add_user_keys(username, &keys);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!("could not read {ak_path:?}: {e}");
                }
            }
        }

        Ok(ak)
    }

    /// Reload keys for a single user. Removes old keys for that user first.
    pub fn reload_user(&mut self, username: &str, ak_path: &Path) -> Result<()> {
        self.remove_user(username);
        let keys = Self::load_file(ak_path)?;
        if !keys.is_empty() {
            tracing::info!(
                "reloaded {} key(s) for user '{username}'",
                keys.len()
            );
            self.add_user_keys(username, &keys);
        }
        Ok(())
    }

    /// Add all keys from a user's authorized_keys file.
    pub fn add_user_keys(&mut self, username: &str, keys: &[(VerifyingKey, String)]) {
        for (key, comment) in keys {
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

    /// Get all usernames a pubkey is authorized for.
    pub fn usernames_for_key(&self, pubkey: &VerifyingKey) -> Vec<&str> {
        self.entries
            .get(pubkey.as_bytes())
            .map(|entries| entries.iter().map(|e| e.username.as_str()).collect())
            .unwrap_or_default()
    }

    /// Remove all keys for a specific user (for rescanning).
    pub fn remove_user(&mut self, username: &str) {
        for entries in self.entries.values_mut() {
            entries.retain(|e| e.username != username);
        }
        self.entries.retain(|_, entries| !entries.is_empty());
    }
}
