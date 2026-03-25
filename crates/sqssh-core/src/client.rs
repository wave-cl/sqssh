use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::config::ClientConfig;
use crate::error::{Error, Result};
use crate::keys;
use crate::known_hosts::KnownHosts;
use crate::protocol::{self, AgentRequest, AgentResponse};

/// Parsed remote destination.
pub struct RemoteSpec {
    pub user: String,
    pub host: String,
    pub path: Option<String>,
}

/// Parse a destination string like "user@host:/path" or "user@host" or "host:/path".
pub fn parse_remote(s: &str) -> Option<RemoteSpec> {
    // Must contain ':' for a path, or '@' for user
    let (userhost, path) = if let Some(colon) = s.find(':') {
        let path = &s[colon + 1..];
        let userhost = &s[..colon];
        (userhost, if path.is_empty() { None } else { Some(path.to_string()) })
    } else {
        // No colon — could be user@host (no path) for sqssh, but not a remote spec for sqscp
        return None;
    };

    let (user, host) = if let Some(at) = userhost.find('@') {
        (Some(userhost[..at].to_string()), userhost[at + 1..].to_string())
    } else {
        (None, userhost.to_string())
    };

    Some(RemoteSpec {
        user: user.unwrap_or_else(|| whoami::username()),
        host,
        path,
    })
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
) -> Result<Connection> {
    let sqssh_dir = keys::sqssh_dir()?;
    let config = ClientConfig::load(&sqssh_dir.join("config"))?;
    let resolved = config.resolve(host);

    let actual_host = resolved.hostname.as_deref().unwrap_or(host);
    let port = port.unwrap_or(resolved.port);
    let username = user
        .map(String::from)
        .or(resolved.user.clone())
        .unwrap_or_else(|| whoami::username());

    // Resolve server public key
    let server_pubkey = if let Some(ref hk) = resolved.host_key {
        keys::decode_pubkey(hk)?
    } else {
        let known_hosts = KnownHosts::load(&sqssh_dir.join("known_hosts"))?;
        *known_hosts
            .lookup(actual_host)
            .ok_or_else(|| Error::UnknownHost(actual_host.to_string()))?
    };

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
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let sk = keys::load_private_key(&path)?;
        let vk = sk.verifying_key();
        tracing::debug!("using explicit identity: {}", path.display());
        (sk, vk, name)
    } else if let Some(ref config_id) = resolved.identity_file {
        let path = PathBuf::from(config_id);
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let sk = keys::load_private_key(&path)?;
        let vk = sk.verifying_key();
        tracing::debug!("using config IdentityFile: {}", path.display());
        (sk, vk, name)
    } else if let Some((sk, vk)) = try_agent_key() {
        tracing::debug!("using key from agent");
        (sk, vk, String::new()) // agent keys don't map to a file
    } else if let Some(mapped_path) = keys::key_for_host(host) {
        let name = mapped_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
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
        .write_all(&protocol::encode_auth_request(&username, verifying_key.as_bytes()))
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
        AgentResponse::Keys { entries } if !entries.is_empty() => {
            entries[0].pubkey.clone()
        }
        _ => return None,
    };

    if pubkey_bytes.len() != 32 {
        return None;
    }

    // Get seed from agent
    let mut stream = UnixStream::connect(&socket_path).ok()?;
    let data = AgentRequest::GetSeed {
        pubkey: pubkey_bytes.clone(),
    }.encode();
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
