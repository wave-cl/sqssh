use std::fs;
use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::error::{Error, Result};
use crate::keys::{decode_pubkey, encode_pubkey};

/// A single entry in the known_hosts file.
#[derive(Debug, Clone)]
pub struct KnownHostEntry {
    pub pattern: String,
    pub pubkey: VerifyingKey,
    pub comment: String,
}

/// The known_hosts database.
#[derive(Debug, Default)]
pub struct KnownHosts {
    entries: Vec<KnownHostEntry>,
}

impl KnownHosts {
    /// Load known_hosts from a file. Returns empty database if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)?;
        let mut entries = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match parse_known_host_line(line) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    tracing::warn!("known_hosts line {}: {e}", line_num + 1);
                }
            }
        }

        Ok(Self { entries })
    }

    /// Look up a host's public key.
    pub fn lookup(&self, hostname: &str) -> Option<&VerifyingKey> {
        self.entries
            .iter()
            .find(|e| pattern_matches(&e.pattern, hostname))
            .map(|e| &e.pubkey)
    }

    /// Add a host entry. If the host already exists, update its key.
    pub fn add(&mut self, hostname: &str, pubkey: VerifyingKey, comment: &str) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.pattern == hostname)
        {
            entry.pubkey = pubkey;
            entry.comment = comment.to_string();
        } else {
            self.entries.push(KnownHostEntry {
                pattern: hostname.to_string(),
                pubkey,
                comment: comment.to_string(),
            });
        }
    }

    /// Remove a host entry. Returns true if found and removed.
    pub fn remove(&mut self, hostname: &str) -> bool {
        let len_before = self.entries.len();
        self.entries.retain(|e| e.pattern != hostname);
        self.entries.len() != len_before
    }

    /// Save the database to a file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut content = String::new();
        for entry in &self.entries {
            let encoded = encode_pubkey(&entry.pubkey);
            if entry.comment.is_empty() {
                content.push_str(&format!("{} {encoded}\n", entry.pattern));
            } else {
                content.push_str(&format!("{} {encoded} {}\n", entry.pattern, entry.comment));
            }
        }
        fs::write(path, content)?;
        Ok(())
    }

    /// List all entries.
    pub fn entries(&self) -> &[KnownHostEntry] {
        &self.entries
    }
}

/// Parse a known_hosts line: "<pattern> <base58-pubkey> [comment]"
fn parse_known_host_line(line: &str) -> Result<KnownHostEntry> {
    let mut parts = line.splitn(3, ' ');

    let pattern = parts
        .next()
        .ok_or_else(|| Error::KnownHosts("missing hostname pattern".into()))?
        .to_string();

    let key_data = parts
        .next()
        .ok_or_else(|| Error::KnownHosts("missing public key".into()))?;

    let pubkey = decode_pubkey(key_data)
        .map_err(|e| Error::KnownHosts(format!("invalid key for '{pattern}': {e}")))?;

    let comment = parts.next().unwrap_or("").to_string();

    Ok(KnownHostEntry {
        pattern,
        pubkey,
        comment,
    })
}

/// Match a hostname against a pattern with `*` and `?` glob support. (public for config module)
pub fn pattern_matches_pub(pattern: &str, hostname: &str) -> bool {
    glob_match(pattern.as_bytes(), hostname.as_bytes())
}

fn pattern_matches(pattern: &str, hostname: &str) -> bool {
    glob_match(pattern.as_bytes(), hostname.as_bytes())
}

fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0;
    let mut ti = 0;
    let mut star_pi = usize::MAX;
    let mut star_ti = 0;

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_keypair;

    #[test]
    fn test_pattern_matching() {
        assert!(pattern_matches("example.com", "example.com"));
        assert!(!pattern_matches("example.com", "other.com"));
        assert!(pattern_matches("*.example.com", "dev.example.com"));
        assert!(!pattern_matches("*.example.com", "example.com"));
        assert!(pattern_matches("prod-*", "prod-web-01"));
        assert!(pattern_matches("192.168.1.?", "192.168.1.5"));
        assert!(!pattern_matches("192.168.1.?", "192.168.1.55"));
        assert!(pattern_matches("*", "anything"));
    }

    #[test]
    fn test_known_hosts_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");

        let (_, key1) = generate_keypair();
        let (_, key2) = generate_keypair();

        let mut kh = KnownHosts::default();
        kh.add("host1.example.com", key1, "");
        kh.add("host2.example.com", key2, "prod server");
        kh.save(&path).unwrap();

        let loaded = KnownHosts::load(&path).unwrap();
        assert_eq!(loaded.entries().len(), 2);
        assert_eq!(loaded.lookup("host1.example.com"), Some(&key1));
        assert_eq!(loaded.lookup("host2.example.com"), Some(&key2));
        assert_eq!(loaded.lookup("unknown.com"), None);
    }

    #[test]
    fn test_known_hosts_remove() {
        let mut kh = KnownHosts::default();
        let (_, key) = generate_keypair();
        kh.add("host.com", key, "");
        assert!(kh.remove("host.com"));
        assert!(!kh.remove("host.com"));
        assert_eq!(kh.lookup("host.com"), None);
    }
}
