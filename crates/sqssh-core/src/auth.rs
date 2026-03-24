use std::collections::HashMap;
use std::fs;
use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::error::{Error, Result};
use crate::keys::{decode_pubkey, encode_pubkey, parse_public_key_line};

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
    /// Load authorized_keys for a specific user from their file.
    pub fn load_for_user(username: &str, path: &Path) -> Result<Vec<VerifyingKey>> {
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
                Ok((key, _comment)) => keys.push(key),
                Err(e) => tracing::warn!("skipping invalid authorized_keys entry: {e}"),
            }
        }

        Ok(keys)
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
