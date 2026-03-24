//! Session persistence for server restarts.

use serde::{Deserialize, Serialize};

/// Metadata for a persisted PTY session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSession {
    pub username: String,
    pub client_pubkey: [u8; 32],
    pub term: String,
    pub cols: u16,
    pub rows: u16,
    pub child_pid: u32,
    pub home: String,
    pub shell: String,
}

/// A collection of persisted sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistPayload {
    pub sessions: Vec<PersistedSession>,
}

impl PersistPayload {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        rmp_serde::to_vec(self).map_err(|e| e.to_string())
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        rmp_serde::from_slice(data).map_err(|e| e.to_string())
    }
}
