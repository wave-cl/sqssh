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
