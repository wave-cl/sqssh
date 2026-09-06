use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::config::{ClientConfig, ResolvedConfig};
use crate::error::{Error, Result};
use crate::keys;
use crate::known_hosts::KnownHosts;
use crate::protocol::{self, AgentRequest, AgentResponse};

/// Parsed remote destination.
pub struct RemoteSpec {
    /// `None` when the destination named no user.
    ///
    /// Deliberately not defaulted to the local username here. Doing that made
    /// `host:path` indistinguishable from `me@host:path` by the time config
    /// resolution ran, so a `Host` block's `User` could never take effect —
    /// `sqssh ex` connected as root and `sqscp file ex:/tmp/x` did not.
    pub user: Option<String>,
    pub host: String,
    pub path: Option<String>,
}

/// Parse a destination string like "user@host:/path" or "user@host" or "host:/path".
pub fn parse_remote(s: &str) -> Option<RemoteSpec> {
    // No colon — could be user@host (no path) for sqssh, but not a remote spec
    // for sqscp, so this is not a destination we can parse.
    let colon = s.find(':')?;
    let userhost = &s[..colon];
    let path = &s[colon + 1..];
    let path = if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    };

    let (user, host) = if let Some(at) = userhost.find('@') {
        (
            Some(userhost[..at].to_string()),
            userhost[at + 1..].to_string(),
        )
    } else {
        (None, userhost.to_string())
    };

    Some(RemoteSpec { user, host, path })
}

/// Which server key to pin for this connection.
///
/// A `HostKey` — from the config or from `-o hostkey=`, which is the same
/// thing by the time it arrives here — wins over `known_hosts`. That order is
/// the whole point of being able to state a key on the command line: it is how
/// you reach a host whose key you have been given but have not written down,
/// and how you override one you have written down and now doubt.
///
/// Worth stating because getting it backwards is invisible in the ordinary
/// case. If `known_hosts` won, a `-o hostkey=` naming the *wrong* key would
/// still connect — silently, via the stored one — and the override would look
/// like it worked. That asymmetry is the only way to tell the two apart from
/// the outside, and it is what the test for this checks.
pub fn server_key(
    resolved: &ResolvedConfig,
    known_hosts: &KnownHosts,
    host: &str,
) -> Result<VerifyingKey> {
    match resolved.host_key {
        Some(ref hk) => keys::decode_pubkey(hk.as_str()),
        None => known_hosts
            .lookup(host)
            .copied()
            .ok_or_else(|| Error::UnknownHost(host.to_string())),
    }
}

/// Established, authenticated connection to a remote sqsshd.
pub struct Connection {
    pub conn: quinn::Connection,
    pub username: String,
    /// The key that succeeded auth (cached for reconnects).
    pub signing_key: ed25519_dalek::SigningKey,
}

/// Connect to a remote sqsshd, authenticate, and return the connection.
pub async fn connect(
    host: &str,
    user: Option<&str>,
    port: Option<u16>,
    identity: Option<&Path>,
    config_file: Option<&Path>,
) -> Result<Connection> {
    let sqssh_dir = keys::sqssh_dir()?;
    let config_path = config_file
        .map(PathBuf::from)
        .unwrap_or_else(|| sqssh_dir.join("config"));
    let config = ClientConfig::load(&config_path)?;
    let resolved = config.resolve(host);

    let actual_host = resolved.hostname.as_deref().unwrap_or(host);
    let port = port.unwrap_or(resolved.port);
    let username = user
        .map(String::from)
        .or(resolved.user.clone())
        .unwrap_or_else(whoami::username);

    // Resolve server public key
    let known_hosts = KnownHosts::load(&sqssh_dir.join("known_hosts"))?;
    let server_pubkey = server_key(&resolved, &known_hosts, actual_host)?;

    // Resolve address
    let addr: SocketAddr = format!("{actual_host}:{port}")
        .to_socket_addrs()
        .map_err(|e| Error::Connection(format!("DNS resolution failed: {e}")))?
        .next()
        .ok_or_else(|| Error::Connection(format!("could not resolve {actual_host}:{port}")))?;

    // Key resolution chain:
    // 1. Explicit -i flag
    // 2. IdentityFile from config
    // 3. Agent
    // 4. Learned key_map for this host
    // 5. Default ~/.sqssh/id_ed25519
    // Key name for key_map (relative to ~/.sqssh/)
    let (signing_key, verifying_key, key_name) = if let Some(id_path) = identity {
        let path = PathBuf::from(id_path);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let sk = keys::load_private_key(&path)?;
        let vk = sk.verifying_key();
        tracing::debug!("using explicit identity: {}", path.display());
        (sk, vk, name)
    } else if let Some(ref config_id) = resolved.identity_file {
        let path = PathBuf::from(config_id);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let sk = keys::load_private_key(&path)?;
        let vk = sk.verifying_key();
        tracing::debug!("using config IdentityFile: {}", path.display());
        (sk, vk, name)
    } else if let Some((sk, vk)) = try_agent_key() {
        tracing::debug!("using key from agent");
        (sk, vk, String::new()) // agent keys don't map to a file
    } else if let Some(mapped_path) = keys::key_for_host(host) {
        let name = mapped_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let sk = keys::load_private_key(&mapped_path)?;
        let vk = sk.verifying_key();
        tracing::debug!("using key_map: {}", mapped_path.display());
        (sk, vk, name)
    } else {
        let path = sqssh_dir.join("id_ed25519");
        let sk = keys::load_private_key(&path)?;
        let vk = sk.verifying_key();
        tracing::debug!("using default key");
        (sk, vk, "id_ed25519".into())
    };

    // Connect via squic
    let client_key_hex = signing_key
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let squic_config = squic::Config {
        alpn_protocols: vec![protocol::ALPN.to_vec()],
        keep_alive: Some(std::time::Duration::from_secs(resolved.keepalive_interval)),
        client_key: Some(client_key_hex),
        handshake_timeout: Some(std::time::Duration::from_secs(resolved.connect_timeout)),
        ..Default::default()
    };

    // Only override squic's own default when the config actually named a
    // version; see ResolvedConfig::envelope_version.
    let mut squic_config = squic_config;
    crate::config::apply_client_envelope_version(&mut squic_config, &resolved);

    let conn = squic::dial(addr, server_pubkey.as_bytes(), squic_config)
        .await
        .map_err(|e| {
            let hint = crate::error::format_connection_error(&e.to_string());
            Error::Connection(hint)
        })?;

    // Authenticate on stream 0 (raw binary)
    let (mut auth_send, mut auth_recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::Connection(format!("failed to open auth stream: {e}")))?;
    auth_send
        .write_all(&protocol::encode_auth_request(
            &username,
            verifying_key.as_bytes(),
        ))
        .await
        .map_err(|e| Error::Connection(format!("failed to send auth request: {e}")))?;

    match protocol::decode_auth_response(&mut auth_recv).await? {
        protocol::AuthResponseData::Success => {
            // Auto-learn: save which key worked for this host
            if !key_name.is_empty() {
                keys::save_key_mapping(host, &key_name).ok();
            }
        }
        protocol::AuthResponseData::Failure { message } => {
            return Err(Error::Auth(format!("authentication failed: {message}")));
        }
    }

    Ok(Connection {
        conn,
        username,
        signing_key,
    })
}

/// Try to get a key from the running sqssh-agent.
/// Returns None if agent is unavailable or has no keys.
fn try_agent_key() -> Option<(SigningKey, VerifyingKey)> {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    let socket_path = std::env::var("SQSSH_AGENT_SOCK")
        .map(PathBuf::from)
        .or_else(|_| keys::sqssh_dir().map(|d| d.join("agent.sock")))
        .ok()?;

    let mut stream = UnixStream::connect(&socket_path).ok()?;

    // List keys
    let data = AgentRequest::ListKeys.encode();
    stream.write_all(&data).ok()?;
    let response = AgentResponse::decode(&mut stream).ok()?;

    let pubkey_bytes = match response {
        AgentResponse::Keys { entries } if !entries.is_empty() => entries[0].pubkey.clone(),
        _ => return None,
    };

    if pubkey_bytes.len() != 32 {
        return None;
    }

    // Get seed from agent
    let mut stream = UnixStream::connect(&socket_path).ok()?;
    let data = AgentRequest::GetSeed {
        pubkey: pubkey_bytes.clone(),
    }
    .encode();
    stream.write_all(&data).ok()?;
    let response = AgentResponse::decode(&mut stream).ok()?;

    match response {
        AgentResponse::Seed { seed } if seed.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&seed);
            let sk = SigningKey::from_bytes(&arr);
            let vk = sk.verifying_key();
            Some((sk, vk))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    /// Give it the **wrong** key and it must refuse to fall back.
    ///
    /// This is the only way to tell an honoured `-o hostkey=` from an ignored
    /// one from the outside. With the right key both behave identically —
    /// which is how the override looked fixed while it was still being
    /// discarded, and known_hosts was quietly supplying the answer. So the
    /// test states a key that is *valid but not this host's* and requires it
    /// to be the one pinned.
    #[test]
    fn a_host_key_override_is_used_even_when_it_is_the_wrong_key() {
        let stored = key(1); // what known_hosts holds for "ex"
        let other = key(2); // a real key, belonging to some other host

        let mut known = KnownHosts::default();
        known.add("ex", stored, "stored");

        let cfg = ClientConfig::parse("").expect("empty config parses");

        // No override: known_hosts answers.
        let plain = cfg.resolve("ex");
        assert_eq!(
            server_key(&plain, &known, "ex").expect("known host"),
            stored
        );

        // Override naming a different host's key: that key is pinned, and the
        // stored one is not consulted. If this ever returns `stored`, an
        // override is decorative and a wrong key connects anyway.
        let overridden = cfg
            .resolve_with("ex", &[format!("hostkey={}", keys::encode_pubkey(&other))])
            .expect("override applies");
        let pinned = server_key(&overridden, &known, "ex").expect("override pins");
        assert_eq!(pinned, other, "the override must win over known_hosts");
        assert_ne!(pinned, stored, "known_hosts must not have supplied it");

        // A config `HostKey` behaves the same way — `-o` and the file reach
        // this by the same route, which is why one test covers both.
        let from_file = ClientConfig::parse(&format!(
            "Host ex\n    HostKey {}\n",
            keys::encode_pubkey(&other)
        ))
        .expect("parses");
        assert_eq!(
            server_key(&from_file.resolve("ex"), &known, "ex").expect("file pins"),
            other
        );

        // Neither source: an unknown host, not a silent guess.
        assert!(matches!(
            server_key(&cfg.resolve("nowhere"), &known, "nowhere"),
            Err(Error::UnknownHost(_))
        ));

        // A malformed override is refused rather than falling back.
        let bad = cfg
            .resolve_with("ex", &["hostkey=not-a-key".into()])
            .expect("resolves");
        assert!(server_key(&bad, &known, "ex").is_err());
    }
}
