//! Session persistence for server restarts.

/// Metadata for a persisted PTY session.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct PersistPayload {
    pub sessions: Vec<PersistedSession>,
}

impl PersistPayload {
    /// Encode to binary:
    /// [4 bytes count][sessions...]
    /// Each session: [2 bytes username_len][username][32 bytes pubkey]
    ///               [2 bytes term_len][term][2 bytes cols][2 bytes rows]
    ///               [4 bytes child_pid][2 bytes home_len][home][2 bytes shell_len][shell]
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.sessions.len() as u32).to_be_bytes());
        for s in &self.sessions {
            let ub = s.username.as_bytes();
            buf.extend_from_slice(&(ub.len() as u16).to_be_bytes());
            buf.extend_from_slice(ub);
            buf.extend_from_slice(&s.client_pubkey);
            let tb = s.term.as_bytes();
            buf.extend_from_slice(&(tb.len() as u16).to_be_bytes());
            buf.extend_from_slice(tb);
            buf.extend_from_slice(&s.cols.to_be_bytes());
            buf.extend_from_slice(&s.rows.to_be_bytes());
            buf.extend_from_slice(&s.child_pid.to_be_bytes());
            let hb = s.home.as_bytes();
            buf.extend_from_slice(&(hb.len() as u16).to_be_bytes());
            buf.extend_from_slice(hb);
            let sb = s.shell.as_bytes();
            buf.extend_from_slice(&(sb.len() as u16).to_be_bytes());
            buf.extend_from_slice(sb);
        }
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Result<Self, String> {
        let mut pos = 0;

        let read_u16 = |data: &[u8], pos: &mut usize| -> Result<u16, String> {
            if *pos + 2 > data.len() { return Err("truncated".into()); }
            let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Ok(v)
        };
        let read_u32 = |data: &[u8], pos: &mut usize| -> Result<u32, String> {
            if *pos + 4 > data.len() { return Err("truncated".into()); }
            let v = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
            *pos += 4;
            Ok(v)
        };
        let read_str = |data: &[u8], pos: &mut usize, len: usize| -> Result<String, String> {
            if *pos + len > data.len() { return Err("truncated".into()); }
            let s = String::from_utf8(data[*pos..*pos + len].to_vec())
                .map_err(|_| "invalid UTF-8".to_string())?;
            *pos += len;
            Ok(s)
        };
        let read_bytes = |data: &[u8], pos: &mut usize, len: usize| -> Result<Vec<u8>, String> {
            if *pos + len > data.len() { return Err("truncated".into()); }
            let b = data[*pos..*pos + len].to_vec();
            *pos += len;
            Ok(b)
        };

        let count = read_u32(data, &mut pos)? as usize;
        let mut sessions = Vec::with_capacity(count);

        for _ in 0..count {
            let ulen = read_u16(data, &mut pos)? as usize;
            let username = read_str(data, &mut pos, ulen)?;
            let pk = read_bytes(data, &mut pos, 32)?;
            let mut client_pubkey = [0u8; 32];
            client_pubkey.copy_from_slice(&pk);
            let tlen = read_u16(data, &mut pos)? as usize;
            let term = read_str(data, &mut pos, tlen)?;
            let cols = read_u16(data, &mut pos)?;
            let rows = read_u16(data, &mut pos)?;
            let child_pid = read_u32(data, &mut pos)?;
            let hlen = read_u16(data, &mut pos)? as usize;
            let home = read_str(data, &mut pos, hlen)?;
            let slen = read_u16(data, &mut pos)? as usize;
            let shell = read_str(data, &mut pos, slen)?;

            sessions.push(PersistedSession {
                username,
                client_pubkey,
                term,
                cols,
                rows,
                child_pid,
                home,
                shell,
            });
        }

        Ok(Self { sessions })
    }
}
