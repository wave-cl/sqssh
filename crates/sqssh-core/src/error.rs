use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("key error: {0}")]
    Key(String),

    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("base58 decode error: {0}")]
    Base58Decode(#[from] bs58::decode::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("known_hosts error: {0}")]
    KnownHosts(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("connection error: {0}")]
    Connection(String),

    #[error("unknown host: no server key for '{0}'. Add the server's public key to ~/.sqssh/known_hosts or config.")]
    UnknownHost(String),

    #[error("host key mismatch for '{host}': expected {expected}, got {actual}")]
    HostKeyMismatch {
        host: String,
        expected: String,
        actual: String,
    },

    #[error("serialization error: {0}")]
    Serialization(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Format a connection error with actionable hints.
pub fn format_connection_error(err: &str) -> String {
    let msg = err.to_lowercase();
    if msg.contains("timed out") {
        format!(
            "connection timed out\n  \
             - server may not be running (sqsshd)\n  \
             - host may be unreachable or firewalled\n  \
             - wrong port (default: 22/UDP)\n  \
             - your key is not in the server's whitelist (silent drop)"
        )
    } else if msg.contains("connection refused") {
        "connection refused\n  \
         - no service listening on that port"
            .to_string()
    } else if msg.contains("network unreachable") || msg.contains("no route to host") {
        "network unreachable\n  \
         - no route to host — check your internet connection"
            .to_string()
    } else if msg.contains("dns") || msg.contains("resolve") {
        format!("DNS resolution failed\n  \
                 - hostname could not be resolved — check spelling")
    } else {
        err.to_string()
    }
}
