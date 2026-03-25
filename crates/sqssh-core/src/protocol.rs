use crate::error::{Error, Result};

/// ALPN protocol identifier.
pub const ALPN: &[u8] = b"sqssh/1";

/// Default sqssh port (UDP).
pub const DEFAULT_PORT: u16 = 22;

#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub is_dir: bool,
    pub mtime: u64,
    pub atime: u64,
}

// -- Control socket protocol (Unix domain socket, sqsshctl ↔ sqsshd) --
// Binary format:
//   Request:  [1 byte type] — 0x01 ReloadKeys, 0x02 ReloadAllKeys
//   Response: [1 byte type][2 bytes msg_len][message] — 0x10 Ok, 0x11 Error

const CTL_RELOAD_KEYS: u8 = 0x01;
const CTL_RELOAD_ALL_KEYS: u8 = 0x02;
const CTL_RESP_OK: u8 = 0x10;
const CTL_RESP_ERROR: u8 = 0x11;

/// Request from sqsshctl to sqsshd over the control socket.
#[derive(Debug, Clone)]
pub enum CtlRequest {
    ReloadKeys,
    ReloadAllKeys,
}

/// Response from sqsshd to sqsshctl over the control socket.
#[derive(Debug, Clone)]
pub enum CtlResponse {
    Ok { message: String },
    Error { message: String },
}

impl CtlRequest {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::ReloadKeys => vec![CTL_RELOAD_KEYS],
            Self::ReloadAllKeys => vec![CTL_RELOAD_ALL_KEYS],
        }
    }

    pub fn decode(reader: &mut impl std::io::Read) -> Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)
            .map_err(|e| Error::Connection(format!("ctl request type: {e}")))?;
        match buf[0] {
            CTL_RELOAD_KEYS => Ok(Self::ReloadKeys),
            CTL_RELOAD_ALL_KEYS => Ok(Self::ReloadAllKeys),
            other => Err(Error::Protocol(format!("unknown ctl request: {other:#x}"))),
        }
    }

    pub async fn decode_async(recv: &mut (impl tokio::io::AsyncReadExt + Unpin)) -> Result<Self> {
        let mut buf = [0u8; 1];
        recv.read_exact(&mut buf).await
            .map_err(|e| Error::Connection(format!("ctl request type: {e}")))?;
        match buf[0] {
            CTL_RELOAD_KEYS => Ok(Self::ReloadKeys),
            CTL_RELOAD_ALL_KEYS => Ok(Self::ReloadAllKeys),
            other => Err(Error::Protocol(format!("unknown ctl request: {other:#x}"))),
        }
    }
}

impl CtlResponse {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ok { message } | Self::Error { message } => {
                let typ = if matches!(self, Self::Ok { .. }) { CTL_RESP_OK } else { CTL_RESP_ERROR };
                let mb = message.as_bytes();
                let mut buf = Vec::with_capacity(1 + 2 + mb.len());
                buf.push(typ);
                buf.extend_from_slice(&(mb.len() as u16).to_be_bytes());
                buf.extend_from_slice(mb);
                buf
            }
        }
    }

    pub fn decode(reader: &mut impl std::io::Read) -> Result<Self> {
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf)
            .map_err(|e| Error::Connection(format!("ctl response type: {e}")))?;
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf)
            .map_err(|e| Error::Connection(format!("ctl response len: {e}")))?;
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; len];
        if len > 0 {
            reader.read_exact(&mut msg_buf)
                .map_err(|e| Error::Connection(format!("ctl response msg: {e}")))?;
        }
        let message = String::from_utf8(msg_buf).unwrap_or_default();
        match type_buf[0] {
            CTL_RESP_OK => Ok(Self::Ok { message }),
            CTL_RESP_ERROR => Ok(Self::Error { message }),
            other => Err(Error::Protocol(format!("unknown ctl response: {other:#x}"))),
        }
    }
}

// -- Raw auth protocol (bidi stream 0) --

/// Auth request type byte.
pub const AUTH_REQUEST: u8 = 0x01;
/// Auth success type byte.
pub const AUTH_SUCCESS: u8 = 0x02;
/// Auth failure type byte.
pub const AUTH_FAILURE: u8 = 0x03;

/// Encode an auth request: [1 byte: AUTH_REQUEST][2 bytes username_len][username][32 bytes pubkey]
pub fn encode_auth_request(username: &str, pubkey: &[u8; 32]) -> Vec<u8> {
    let uname = username.as_bytes();
    let mut buf = Vec::with_capacity(1 + 2 + uname.len() + 32);
    buf.push(AUTH_REQUEST);
    buf.extend_from_slice(&(uname.len() as u16).to_be_bytes());
    buf.extend_from_slice(uname);
    buf.extend_from_slice(pubkey);
    buf
}

/// Encode an auth success response: [1 byte: AUTH_SUCCESS]
pub fn encode_auth_success() -> Vec<u8> {
    vec![AUTH_SUCCESS]
}

/// Encode an auth failure response: [1 byte: AUTH_FAILURE][2 bytes msg_len][message]
pub fn encode_auth_failure(message: &str) -> Vec<u8> {
    let msg = message.as_bytes();
    let mut buf = Vec::with_capacity(1 + 2 + msg.len());
    buf.push(AUTH_FAILURE);
    buf.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    buf.extend_from_slice(msg);
    buf
}

/// Decoded auth request fields.
pub struct AuthRequestData {
    pub username: String,
    pub pubkey: [u8; 32],
}

/// Decode an auth request from a recv stream (type byte already consumed).
pub async fn decode_auth_request(recv: &mut quinn::RecvStream) -> Result<AuthRequestData> {
    let mut ulen_buf = [0u8; 2];
    recv.read_exact(&mut ulen_buf).await
        .map_err(|e| Error::Connection(format!("auth request username len: {e}")))?;
    let ulen = u16::from_be_bytes(ulen_buf) as usize;
    if ulen > 256 {
        return Err(Error::Protocol("username too long".into()));
    }
    let mut uname_buf = vec![0u8; ulen];
    recv.read_exact(&mut uname_buf).await
        .map_err(|e| Error::Connection(format!("auth request username: {e}")))?;
    let username = String::from_utf8(uname_buf)
        .map_err(|_| Error::Protocol("invalid UTF-8 in username".into()))?;
    let mut pubkey = [0u8; 32];
    recv.read_exact(&mut pubkey).await
        .map_err(|e| Error::Connection(format!("auth request pubkey: {e}")))?;
    Ok(AuthRequestData { username, pubkey })
}

/// Decoded auth response.
pub enum AuthResponseData {
    Success,
    Failure { message: String },
}

/// Decode an auth response from a recv stream (reads type byte).
pub async fn decode_auth_response(recv: &mut quinn::RecvStream) -> Result<AuthResponseData> {
    let mut type_buf = [0u8; 1];
    recv.read_exact(&mut type_buf).await
        .map_err(|e| Error::Connection(format!("auth response type: {e}")))?;
    match type_buf[0] {
        AUTH_SUCCESS => Ok(AuthResponseData::Success),
        AUTH_FAILURE => {
            let mut mlen_buf = [0u8; 2];
            recv.read_exact(&mut mlen_buf).await
                .map_err(|e| Error::Connection(format!("auth failure msg len: {e}")))?;
            let mlen = u16::from_be_bytes(mlen_buf) as usize;
            let mut msg_buf = vec![0u8; mlen];
            if mlen > 0 {
                recv.read_exact(&mut msg_buf).await
                    .map_err(|e| Error::Connection(format!("auth failure msg: {e}")))?;
            }
            let message = String::from_utf8(msg_buf).unwrap_or_default();
            Ok(AuthResponseData::Failure { message })
        }
        other => Err(Error::Protocol(format!("unknown auth response type: {other:#x}"))),
    }
}

// -- Raw exec protocol --

/// Stream type byte: raw exec (client opens bidi stream).
pub const RAW_EXEC: u8 = 0xB2;
/// Stream type byte: raw exec stderr (server opens uni stream).
pub const RAW_EXEC_STDERR: u8 = 0xB3;

// -- Raw file transfer protocol (uni streams, no msgpack) --

/// Stream type byte: upload (client → server uni stream).
pub const RAW_UPLOAD: u8 = 0xA0;
/// Stream type byte: download data (server → client uni stream).
pub const RAW_DOWNLOAD_DATA: u8 = 0xA1;
/// Stream type byte: download request (on metadata bidi stream).
pub const RAW_DOWNLOAD_REQUEST: u8 = 0xA2;
/// Stream type byte: manifest request (on metadata bidi stream).
pub const RAW_MANIFEST_REQUEST: u8 = 0xA3;
/// Stream type byte: manifest response (on metadata bidi stream).
pub const RAW_MANIFEST_RESPONSE: u8 = 0xA4;
/// Stream type byte: transfer result (on metadata bidi stream).
pub const RAW_TRANSFER_RESULT: u8 = 0xA5;
/// Stream type byte: chunked upload (client → server uni stream, with offset).
pub const RAW_UPLOAD_CHUNK: u8 = 0xA6;
/// Stream type byte: chunked download data (server → client uni stream, with offset).
pub const RAW_DOWNLOAD_CHUNK: u8 = 0xA7;

/// Chunk size for raw file transfers (256 KB).
pub const RAW_CHUNK_SIZE: usize = 256 * 1024;

// -- Raw shell protocol (bidi streams, no msgpack) --

/// Stream type byte: raw shell data (bidi stream).
pub const RAW_SHELL: u8 = 0xB0;
/// Stream type byte: shell control messages (bidi stream).
pub const SHELL_CONTROL: u8 = 0xB1;

// Shell control message types
const SHELL_CTRL_WINDOW_CHANGE: u8 = 0x01;
const SHELL_CTRL_EXIT_STATUS: u8 = 0x02;
const SHELL_CTRL_EOF: u8 = 0x03;

/// Header sent at the start of a RAW_SHELL bidi stream.
/// [1 byte: RAW_SHELL][2 bytes: term_len][term][4 bytes: cols][4 bytes: rows]
#[derive(Debug, Clone)]
pub struct RawShellHeader {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
}

impl RawShellHeader {
    pub fn encode(&self) -> Vec<u8> {
        let term_bytes = self.term.as_bytes();
        let mut buf = Vec::with_capacity(1 + 2 + term_bytes.len() + 8);
        buf.push(RAW_SHELL);
        buf.extend_from_slice(&(term_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(term_bytes);
        buf.extend_from_slice(&self.cols.to_be_bytes());
        buf.extend_from_slice(&self.rows.to_be_bytes());
        buf
    }

    pub async fn decode(recv: &mut quinn::RecvStream) -> Result<Self> {
        let mut term_len_buf = [0u8; 2];
        recv.read_exact(&mut term_len_buf).await
            .map_err(|e| Error::Connection(format!("shell header term len: {e}")))?;
        let term_len = u16::from_be_bytes(term_len_buf) as usize;
        if term_len > 256 {
            return Err(Error::Protocol("term string too long".into()));
        }
        let mut term_buf = vec![0u8; term_len];
        recv.read_exact(&mut term_buf).await
            .map_err(|e| Error::Connection(format!("shell header term: {e}")))?;
        let term = String::from_utf8(term_buf)
            .map_err(|_| Error::Protocol("invalid UTF-8 in term".into()))?;
        let mut dims = [0u8; 8];
        recv.read_exact(&mut dims).await
            .map_err(|e| Error::Connection(format!("shell header dims: {e}")))?;
        Ok(Self {
            term,
            cols: u32::from_be_bytes(dims[0..4].try_into().unwrap()),
            rows: u32::from_be_bytes(dims[4..8].try_into().unwrap()),
        })
    }
}

/// Control messages sent on the SHELL_CONTROL bidi stream.
#[derive(Debug, Clone)]
pub enum ShellControlMsg {
    WindowChange { cols: u32, rows: u32 },
    ExitStatus { code: u32 },
    Eof,
}

impl ShellControlMsg {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::WindowChange { cols, rows } => {
                let mut buf = Vec::with_capacity(9);
                buf.push(SHELL_CTRL_WINDOW_CHANGE);
                buf.extend_from_slice(&cols.to_be_bytes());
                buf.extend_from_slice(&rows.to_be_bytes());
                buf
            }
            Self::ExitStatus { code } => {
                let mut buf = Vec::with_capacity(5);
                buf.push(SHELL_CTRL_EXIT_STATUS);
                buf.extend_from_slice(&code.to_be_bytes());
                buf
            }
            Self::Eof => vec![SHELL_CTRL_EOF],
        }
    }

    pub async fn decode(recv: &mut quinn::RecvStream) -> Result<Self> {
        let mut type_buf = [0u8; 1];
        recv.read_exact(&mut type_buf).await
            .map_err(|e| Error::Connection(format!("shell control type: {e}")))?;
        match type_buf[0] {
            SHELL_CTRL_WINDOW_CHANGE => {
                let mut dims = [0u8; 8];
                recv.read_exact(&mut dims).await
                    .map_err(|e| Error::Connection(format!("shell control winchange: {e}")))?;
                Ok(Self::WindowChange {
                    cols: u32::from_be_bytes(dims[0..4].try_into().unwrap()),
                    rows: u32::from_be_bytes(dims[4..8].try_into().unwrap()),
                })
            }
            SHELL_CTRL_EXIT_STATUS => {
                let mut code_buf = [0u8; 4];
                recv.read_exact(&mut code_buf).await
                    .map_err(|e| Error::Connection(format!("shell control exit: {e}")))?;
                Ok(Self::ExitStatus {
                    code: u32::from_be_bytes(code_buf),
                })
            }
            SHELL_CTRL_EOF => Ok(Self::Eof),
            other => Err(Error::Protocol(format!("unknown shell control type: {other:#x}"))),
        }
    }
}

/// Header sent at the start of a SHELL_CONTROL bidi stream.
/// [1 byte: SHELL_CONTROL]
/// No additional data — the type byte is sufficient.
pub struct ShellControlHeader;

impl ShellControlHeader {
    pub fn encode() -> Vec<u8> {
        vec![SHELL_CONTROL]
    }
}

/// Raw file header written at the start of a uni stream.
#[derive(Debug, Clone)]
pub struct RawFileHeader {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub atime: u64,
}

impl RawFileHeader {
    /// Encode to binary: [1 byte type][2 bytes path_len][path][8 size][4 mode][8 mtime][8 atime]
    pub fn encode_upload(&self) -> Vec<u8> {
        let path_bytes = self.path.as_bytes();
        let mut buf = Vec::with_capacity(1 + 2 + path_bytes.len() + 8 + 4 + 8 + 8);
        buf.push(RAW_UPLOAD);
        buf.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(path_bytes);
        buf.extend_from_slice(&self.size.to_be_bytes());
        buf.extend_from_slice(&self.mode.to_be_bytes());
        buf.extend_from_slice(&self.mtime.to_be_bytes());
        buf.extend_from_slice(&self.atime.to_be_bytes());
        buf
    }

    /// Encode for download data stream: [1 byte type][2 bytes path_len][path][8 size][4 mode][8 mtime][8 atime]
    pub fn encode_download(&self) -> Vec<u8> {
        let path_bytes = self.path.as_bytes();
        let mut buf = Vec::with_capacity(1 + 2 + path_bytes.len() + 8 + 4 + 8 + 8);
        buf.push(RAW_DOWNLOAD_DATA);
        buf.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(path_bytes);
        buf.extend_from_slice(&self.size.to_be_bytes());
        buf.extend_from_slice(&self.mode.to_be_bytes());
        buf.extend_from_slice(&self.mtime.to_be_bytes());
        buf.extend_from_slice(&self.atime.to_be_bytes());
        buf
    }

    /// Decode from binary after the type byte has been read.
    pub async fn decode(recv: &mut quinn::RecvStream) -> Result<Self> {
        let mut path_len_buf = [0u8; 2];
        recv.read_exact(&mut path_len_buf)
            .await
            .map_err(|e| Error::Connection(format!("failed to read path length: {e}")))?;
        let path_len = u16::from_be_bytes(path_len_buf) as usize;

        if path_len > 4096 {
            return Err(Error::Protocol("path too long".into()));
        }

        let mut path_buf = vec![0u8; path_len];
        recv.read_exact(&mut path_buf)
            .await
            .map_err(|e| Error::Connection(format!("failed to read path: {e}")))?;
        let path = String::from_utf8(path_buf)
            .map_err(|_| Error::Protocol("invalid UTF-8 in path".into()))?;

        let mut meta_buf = [0u8; 28]; // 8 + 4 + 8 + 8
        recv.read_exact(&mut meta_buf)
            .await
            .map_err(|e| Error::Connection(format!("failed to read file metadata: {e}")))?;

        let size = u64::from_be_bytes(meta_buf[0..8].try_into().unwrap());
        let mode = u32::from_be_bytes(meta_buf[8..12].try_into().unwrap());
        let mtime = u64::from_be_bytes(meta_buf[12..20].try_into().unwrap());
        let atime = u64::from_be_bytes(meta_buf[20..28].try_into().unwrap());

        Ok(Self { path, size, mode, mtime, atime })
    }
}

/// Raw chunked file header for parallel single-file transfers.
#[derive(Debug, Clone)]
pub struct RawChunkHeader {
    pub path: String,
    pub file_size: u64,  // total file size
    pub mode: u32,
    pub mtime: u64,
    pub atime: u64,
    pub offset: u64,     // byte offset into the file
    pub chunk_length: u64, // bytes in this chunk
}

impl RawChunkHeader {
    /// Encode for chunked upload: [type][path_len][path][file_size][mode][mtime][atime][offset][chunk_length]
    pub fn encode_upload(&self) -> Vec<u8> {
        let path_bytes = self.path.as_bytes();
        let mut buf = Vec::with_capacity(1 + 2 + path_bytes.len() + 8 + 4 + 8 + 8 + 8 + 8);
        buf.push(RAW_UPLOAD_CHUNK);
        buf.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(path_bytes);
        buf.extend_from_slice(&self.file_size.to_be_bytes());
        buf.extend_from_slice(&self.mode.to_be_bytes());
        buf.extend_from_slice(&self.mtime.to_be_bytes());
        buf.extend_from_slice(&self.atime.to_be_bytes());
        buf.extend_from_slice(&self.offset.to_be_bytes());
        buf.extend_from_slice(&self.chunk_length.to_be_bytes());
        buf
    }

    /// Encode for chunked download.
    pub fn encode_download(&self) -> Vec<u8> {
        let path_bytes = self.path.as_bytes();
        let mut buf = Vec::with_capacity(1 + 2 + path_bytes.len() + 8 + 4 + 8 + 8 + 8 + 8);
        buf.push(RAW_DOWNLOAD_CHUNK);
        buf.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(path_bytes);
        buf.extend_from_slice(&self.file_size.to_be_bytes());
        buf.extend_from_slice(&self.mode.to_be_bytes());
        buf.extend_from_slice(&self.mtime.to_be_bytes());
        buf.extend_from_slice(&self.atime.to_be_bytes());
        buf.extend_from_slice(&self.offset.to_be_bytes());
        buf.extend_from_slice(&self.chunk_length.to_be_bytes());
        buf
    }

    /// Decode from stream after type byte has been read.
    pub async fn decode(recv: &mut quinn::RecvStream) -> Result<Self> {
        let mut path_len_buf = [0u8; 2];
        recv.read_exact(&mut path_len_buf).await
            .map_err(|e| Error::Connection(format!("chunk header path len: {e}")))?;
        let path_len = u16::from_be_bytes(path_len_buf) as usize;
        if path_len > 4096 {
            return Err(Error::Protocol("path too long".into()));
        }

        let mut path_buf = vec![0u8; path_len];
        recv.read_exact(&mut path_buf).await
            .map_err(|e| Error::Connection(format!("chunk header path: {e}")))?;
        let path = String::from_utf8(path_buf)
            .map_err(|_| Error::Protocol("invalid UTF-8 in path".into()))?;

        let mut meta_buf = [0u8; 44]; // 8+4+8+8+8+8
        recv.read_exact(&mut meta_buf).await
            .map_err(|e| Error::Connection(format!("chunk header meta: {e}")))?;

        Ok(Self {
            path,
            file_size: u64::from_be_bytes(meta_buf[0..8].try_into().unwrap()),
            mode: u32::from_be_bytes(meta_buf[8..12].try_into().unwrap()),
            mtime: u64::from_be_bytes(meta_buf[12..20].try_into().unwrap()),
            atime: u64::from_be_bytes(meta_buf[20..28].try_into().unwrap()),
            offset: u64::from_be_bytes(meta_buf[28..36].try_into().unwrap()),
            chunk_length: u64::from_be_bytes(meta_buf[36..44].try_into().unwrap()),
        })
    }
}

/// Encode a manifest response on a metadata bidi stream.
pub fn encode_manifest_response(entries: &[ManifestEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(RAW_MANIFEST_RESPONSE);
    buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for entry in entries {
        let path_bytes = entry.path.as_bytes();
        buf.push(if entry.is_dir { 1 } else { 0 });
        buf.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(path_bytes);
        buf.extend_from_slice(&entry.size.to_be_bytes());
        buf.extend_from_slice(&entry.mode.to_be_bytes());
        buf.extend_from_slice(&entry.mtime.to_be_bytes());
        buf.extend_from_slice(&entry.atime.to_be_bytes());
    }
    buf
}

/// Decode a manifest response from a metadata bidi stream (after type byte read).
pub async fn decode_manifest_response(recv: &mut quinn::RecvStream) -> Result<Vec<ManifestEntry>> {
    let mut count_buf = [0u8; 4];
    recv.read_exact(&mut count_buf)
        .await
        .map_err(|e| Error::Connection(format!("failed to read manifest count: {e}")))?;
    let count = u32::from_be_bytes(count_buf) as usize;

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let mut type_buf = [0u8; 1];
        recv.read_exact(&mut type_buf).await.map_err(|e| Error::Connection(format!("manifest entry: {e}")))?;
        let is_dir = type_buf[0] == 1;

        let mut path_len_buf = [0u8; 2];
        recv.read_exact(&mut path_len_buf).await.map_err(|e| Error::Connection(format!("manifest path len: {e}")))?;
        let path_len = u16::from_be_bytes(path_len_buf) as usize;

        let mut path_buf = vec![0u8; path_len];
        recv.read_exact(&mut path_buf).await.map_err(|e| Error::Connection(format!("manifest path: {e}")))?;
        let path = String::from_utf8(path_buf).map_err(|_| Error::Protocol("invalid UTF-8".into()))?;

        let mut meta_buf = [0u8; 28];
        recv.read_exact(&mut meta_buf).await.map_err(|e| Error::Connection(format!("manifest meta: {e}")))?;

        entries.push(ManifestEntry {
            path,
            size: u64::from_be_bytes(meta_buf[0..8].try_into().unwrap()),
            mode: u32::from_be_bytes(meta_buf[8..12].try_into().unwrap()),
            is_dir,
            mtime: u64::from_be_bytes(meta_buf[12..20].try_into().unwrap()),
            atime: u64::from_be_bytes(meta_buf[20..28].try_into().unwrap()),
        });
    }

    Ok(entries)
}

/// Encode a transfer result: [type][1 byte success][2 byte msg_len][msg]
pub fn encode_transfer_result(success: bool, message: &str) -> Vec<u8> {
    let msg_bytes = message.as_bytes();
    let mut buf = Vec::with_capacity(1 + 1 + 2 + msg_bytes.len());
    buf.push(RAW_TRANSFER_RESULT);
    buf.push(if success { 1 } else { 0 });
    buf.extend_from_slice(&(msg_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(msg_bytes);
    buf
}

/// Decode a path from a metadata stream (after type byte read).
pub async fn decode_path(recv: &mut quinn::RecvStream) -> Result<String> {
    let mut path_len_buf = [0u8; 2];
    recv.read_exact(&mut path_len_buf)
        .await
        .map_err(|e| Error::Connection(format!("failed to read path length: {e}")))?;
    let path_len = u16::from_be_bytes(path_len_buf) as usize;
    if path_len > 4096 {
        return Err(Error::Protocol("path too long".into()));
    }
    let mut path_buf = vec![0u8; path_len];
    recv.read_exact(&mut path_buf)
        .await
        .map_err(|e| Error::Connection(format!("failed to read path: {e}")))?;
    String::from_utf8(path_buf).map_err(|_| Error::Protocol("invalid UTF-8 in path".into()))
}

/// Decode a transfer result (after type byte read).
pub async fn decode_transfer_result(recv: &mut quinn::RecvStream) -> Result<(bool, String)> {
    let mut buf = [0u8; 3];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| Error::Connection(format!("failed to read transfer result: {e}")))?;
    let success = buf[0] == 1;
    let msg_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    let message = if msg_len > 0 {
        let mut msg_buf = vec![0u8; msg_len];
        recv.read_exact(&mut msg_buf).await.map_err(|e| Error::Connection(format!("result msg: {e}")))?;
        String::from_utf8(msg_buf).unwrap_or_default()
    } else {
        String::new()
    };
    Ok((success, message))
}

// -- Raw SFTP protocol (bidi stream, no msgpack) --

/// Stream type byte: raw SFTP session.
pub const RAW_SFTP: u8 = 0xC0;

// SFTP command types
const SFTP_CMD_LIST_DIR: u8 = 0x01;
const SFTP_CMD_STAT: u8 = 0x02;
const SFTP_CMD_MKDIR: u8 = 0x03;
const SFTP_CMD_REMOVE: u8 = 0x04;
const SFTP_CMD_RENAME: u8 = 0x05;
const SFTP_CMD_REALPATH: u8 = 0x06;
const SFTP_CMD_GET: u8 = 0x07;
const SFTP_CMD_PUT: u8 = 0x08;

// SFTP response types
const SFTP_RESP_OK: u8 = 0x10;
const SFTP_RESP_ERROR: u8 = 0x11;
const SFTP_RESP_DIR_LISTING: u8 = 0x12;
const SFTP_RESP_STAT_RESULT: u8 = 0x13;

/// SFTP command sent by client.
#[derive(Debug, Clone)]
pub enum SftpCmd {
    ListDir { path: String },
    Stat { path: String },
    Mkdir { path: String, mode: u32 },
    Remove { path: String },
    Rename { old_path: String, new_path: String },
    Realpath { path: String },
    Get { path: String },
    Put, // file data arrives on a uni stream
}

impl SftpCmd {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::ListDir { path } | Self::Stat { path } | Self::Realpath { path }
            | Self::Remove { path } | Self::Get { path } => {
                let cmd = match self {
                    Self::ListDir { .. } => SFTP_CMD_LIST_DIR,
                    Self::Stat { .. } => SFTP_CMD_STAT,
                    Self::Realpath { .. } => SFTP_CMD_REALPATH,
                    Self::Remove { .. } => SFTP_CMD_REMOVE,
                    Self::Get { .. } => SFTP_CMD_GET,
                    _ => unreachable!(),
                };
                let pb = path.as_bytes();
                let mut buf = Vec::with_capacity(3 + pb.len());
                buf.push(cmd);
                buf.extend_from_slice(&(pb.len() as u16).to_be_bytes());
                buf.extend_from_slice(pb);
                buf
            }
            Self::Mkdir { path, mode } => {
                let pb = path.as_bytes();
                let payload_len = 2 + pb.len() + 4;
                let mut buf = Vec::with_capacity(3 + payload_len);
                buf.push(SFTP_CMD_MKDIR);
                buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
                buf.extend_from_slice(&(pb.len() as u16).to_be_bytes());
                buf.extend_from_slice(pb);
                buf.extend_from_slice(&mode.to_be_bytes());
                buf
            }
            Self::Rename { old_path, new_path } => {
                let ob = old_path.as_bytes();
                let nb = new_path.as_bytes();
                let payload_len = 2 + ob.len() + 2 + nb.len();
                let mut buf = Vec::with_capacity(3 + payload_len);
                buf.push(SFTP_CMD_RENAME);
                buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
                buf.extend_from_slice(&(ob.len() as u16).to_be_bytes());
                buf.extend_from_slice(ob);
                buf.extend_from_slice(&(nb.len() as u16).to_be_bytes());
                buf.extend_from_slice(nb);
                buf
            }
            Self::Put => {
                vec![SFTP_CMD_PUT, 0, 0]
            }
        }
    }

    pub async fn decode(recv: &mut quinn::RecvStream) -> Result<Self> {
        let mut header = [0u8; 3];
        recv.read_exact(&mut header).await
            .map_err(|e| Error::Connection(format!("sftp cmd header: {e}")))?;
        let cmd_type = header[0];
        let payload_len = u16::from_be_bytes([header[1], header[2]]) as usize;

        if payload_len > 8192 {
            return Err(Error::Protocol("sftp payload too large".into()));
        }

        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            recv.read_exact(&mut payload).await
                .map_err(|e| Error::Connection(format!("sftp cmd payload: {e}")))?;
        }

        match cmd_type {
            SFTP_CMD_LIST_DIR => Ok(Self::ListDir {
                path: String::from_utf8(payload).map_err(|_| Error::Protocol("invalid UTF-8".into()))?,
            }),
            SFTP_CMD_STAT => Ok(Self::Stat {
                path: String::from_utf8(payload).map_err(|_| Error::Protocol("invalid UTF-8".into()))?,
            }),
            SFTP_CMD_REALPATH => Ok(Self::Realpath {
                path: String::from_utf8(payload).map_err(|_| Error::Protocol("invalid UTF-8".into()))?,
            }),
            SFTP_CMD_REMOVE => Ok(Self::Remove {
                path: String::from_utf8(payload).map_err(|_| Error::Protocol("invalid UTF-8".into()))?,
            }),
            SFTP_CMD_GET => Ok(Self::Get {
                path: String::from_utf8(payload).map_err(|_| Error::Protocol("invalid UTF-8".into()))?,
            }),
            SFTP_CMD_PUT => Ok(Self::Put),
            SFTP_CMD_MKDIR => {
                if payload.len() < 6 {
                    return Err(Error::Protocol("mkdir payload too short".into()));
                }
                let path_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                if payload.len() < 2 + path_len + 4 {
                    return Err(Error::Protocol("mkdir payload truncated".into()));
                }
                let path = String::from_utf8(payload[2..2 + path_len].to_vec())
                    .map_err(|_| Error::Protocol("invalid UTF-8".into()))?;
                let mode = u32::from_be_bytes(payload[2 + path_len..2 + path_len + 4].try_into().unwrap());
                Ok(Self::Mkdir { path, mode })
            }
            SFTP_CMD_RENAME => {
                if payload.len() < 4 {
                    return Err(Error::Protocol("rename payload too short".into()));
                }
                let old_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                if payload.len() < 2 + old_len + 2 {
                    return Err(Error::Protocol("rename payload truncated".into()));
                }
                let old_path = String::from_utf8(payload[2..2 + old_len].to_vec())
                    .map_err(|_| Error::Protocol("invalid UTF-8".into()))?;
                let off = 2 + old_len;
                let new_len = u16::from_be_bytes([payload[off], payload[off + 1]]) as usize;
                if payload.len() < off + 2 + new_len {
                    return Err(Error::Protocol("rename payload truncated".into()));
                }
                let new_path = String::from_utf8(payload[off + 2..off + 2 + new_len].to_vec())
                    .map_err(|_| Error::Protocol("invalid UTF-8".into()))?;
                Ok(Self::Rename { old_path, new_path })
            }
            other => Err(Error::Protocol(format!("unknown sftp cmd: {other:#x}"))),
        }
    }
}

/// SFTP response sent by server.
#[derive(Debug, Clone)]
pub enum SftpResp {
    Ok { message: String },
    Error { message: String },
    DirListing { entries: Vec<ManifestEntry> },
    StatResult {
        path: String,
        size: u64,
        mode: u32,
        mtime: u64,
        atime: u64,
        is_dir: bool,
    },
}

impl SftpResp {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ok { message } | Self::Error { message } => {
                let typ = if matches!(self, Self::Ok { .. }) { SFTP_RESP_OK } else { SFTP_RESP_ERROR };
                let mb = message.as_bytes();
                let mut buf = Vec::with_capacity(3 + mb.len());
                buf.push(typ);
                buf.extend_from_slice(&(mb.len() as u16).to_be_bytes());
                buf.extend_from_slice(mb);
                buf
            }
            Self::DirListing { entries } => {
                let mut buf = Vec::new();
                buf.push(SFTP_RESP_DIR_LISTING);
                buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
                for entry in entries {
                    let pb = entry.path.as_bytes();
                    buf.push(if entry.is_dir { 1 } else { 0 });
                    buf.extend_from_slice(&(pb.len() as u16).to_be_bytes());
                    buf.extend_from_slice(pb);
                    buf.extend_from_slice(&entry.size.to_be_bytes());
                    buf.extend_from_slice(&entry.mode.to_be_bytes());
                    buf.extend_from_slice(&entry.mtime.to_be_bytes());
                    buf.extend_from_slice(&entry.atime.to_be_bytes());
                }
                buf
            }
            Self::StatResult { path, size, mode, mtime, atime, is_dir } => {
                let pb = path.as_bytes();
                let mut buf = Vec::with_capacity(1 + 2 + pb.len() + 29);
                buf.push(SFTP_RESP_STAT_RESULT);
                buf.extend_from_slice(&(pb.len() as u16).to_be_bytes());
                buf.extend_from_slice(pb);
                buf.extend_from_slice(&size.to_be_bytes());
                buf.extend_from_slice(&mode.to_be_bytes());
                buf.extend_from_slice(&mtime.to_be_bytes());
                buf.extend_from_slice(&atime.to_be_bytes());
                buf.push(if *is_dir { 1 } else { 0 });
                buf
            }
        }
    }

    pub async fn decode(recv: &mut quinn::RecvStream) -> Result<Self> {
        let mut type_buf = [0u8; 1];
        recv.read_exact(&mut type_buf).await
            .map_err(|e| Error::Connection(format!("sftp resp type: {e}")))?;

        match type_buf[0] {
            SFTP_RESP_OK | SFTP_RESP_ERROR => {
                let mut len_buf = [0u8; 2];
                recv.read_exact(&mut len_buf).await
                    .map_err(|e| Error::Connection(format!("sftp resp len: {e}")))?;
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut msg_buf = vec![0u8; len];
                if len > 0 {
                    recv.read_exact(&mut msg_buf).await
                        .map_err(|e| Error::Connection(format!("sftp resp msg: {e}")))?;
                }
                let message = String::from_utf8(msg_buf).unwrap_or_default();
                if type_buf[0] == SFTP_RESP_OK {
                    Ok(Self::Ok { message })
                } else {
                    Ok(Self::Error { message })
                }
            }
            SFTP_RESP_DIR_LISTING => {
                let mut count_buf = [0u8; 4];
                recv.read_exact(&mut count_buf).await
                    .map_err(|e| Error::Connection(format!("sftp dir count: {e}")))?;
                let count = u32::from_be_bytes(count_buf) as usize;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut flags = [0u8; 1];
                    recv.read_exact(&mut flags).await.map_err(|e| Error::Connection(format!("dir entry: {e}")))?;
                    let is_dir = flags[0] == 1;
                    let mut pl = [0u8; 2];
                    recv.read_exact(&mut pl).await.map_err(|e| Error::Connection(format!("dir path len: {e}")))?;
                    let path_len = u16::from_be_bytes(pl) as usize;
                    let mut pb = vec![0u8; path_len];
                    recv.read_exact(&mut pb).await.map_err(|e| Error::Connection(format!("dir path: {e}")))?;
                    let path = String::from_utf8(pb).map_err(|_| Error::Protocol("invalid UTF-8".into()))?;
                    let mut meta = [0u8; 28];
                    recv.read_exact(&mut meta).await.map_err(|e| Error::Connection(format!("dir meta: {e}")))?;
                    entries.push(ManifestEntry {
                        path,
                        size: u64::from_be_bytes(meta[0..8].try_into().unwrap()),
                        mode: u32::from_be_bytes(meta[8..12].try_into().unwrap()),
                        is_dir,
                        mtime: u64::from_be_bytes(meta[12..20].try_into().unwrap()),
                        atime: u64::from_be_bytes(meta[20..28].try_into().unwrap()),
                    });
                }
                Ok(Self::DirListing { entries })
            }
            SFTP_RESP_STAT_RESULT => {
                let mut pl = [0u8; 2];
                recv.read_exact(&mut pl).await.map_err(|e| Error::Connection(format!("stat path len: {e}")))?;
                let path_len = u16::from_be_bytes(pl) as usize;
                let mut pb = vec![0u8; path_len];
                recv.read_exact(&mut pb).await.map_err(|e| Error::Connection(format!("stat path: {e}")))?;
                let path = String::from_utf8(pb).map_err(|_| Error::Protocol("invalid UTF-8".into()))?;
                let mut meta = [0u8; 29];
                recv.read_exact(&mut meta).await.map_err(|e| Error::Connection(format!("stat meta: {e}")))?;
                Ok(Self::StatResult {
                    path,
                    size: u64::from_be_bytes(meta[0..8].try_into().unwrap()),
                    mode: u32::from_be_bytes(meta[8..12].try_into().unwrap()),
                    mtime: u64::from_be_bytes(meta[12..20].try_into().unwrap()),
                    atime: u64::from_be_bytes(meta[20..28].try_into().unwrap()),
                    is_dir: meta[28] == 1,
                })
            }
            other => Err(Error::Protocol(format!("unknown sftp resp: {other:#x}"))),
        }
    }
}

// -- Agent protocol (Unix domain socket, sqssh-agent) --
// Binary format:
//   Request:
//     0x01 AddKey:    [1][32 bytes seed][2 bytes comment_len][comment]
//     0x02 RemoveKey: [1][32 bytes pubkey]
//     0x03 RemoveAll: [1]
//     0x04 ListKeys:  [1]
//     0x05 GetSeed:   [1][32 bytes pubkey]
//   Response:
//     0x10 Ok:    [1]
//     0x11 Error: [1][2 bytes msg_len][message]
//     0x12 Keys:  [1][4 bytes count][entries: 32 bytes pubkey + 2 bytes comment_len + comment]
//     0x13 Seed:  [1][32 bytes seed]

const AGENT_ADD_KEY: u8 = 0x01;
const AGENT_REMOVE_KEY: u8 = 0x02;
const AGENT_REMOVE_ALL: u8 = 0x03;
const AGENT_LIST_KEYS: u8 = 0x04;
const AGENT_GET_SEED: u8 = 0x05;
const AGENT_RESP_OK: u8 = 0x10;
const AGENT_RESP_ERROR: u8 = 0x11;
const AGENT_RESP_KEYS: u8 = 0x12;
const AGENT_RESP_SEED: u8 = 0x13;

/// Request from sqssh-add or client to sqssh-agent.
#[derive(Debug, Clone)]
pub enum AgentRequest {
    AddKey { seed: Vec<u8>, comment: String },
    RemoveKey { pubkey: Vec<u8> },
    RemoveAll,
    ListKeys,
    GetSeed { pubkey: Vec<u8> },
}

/// Response from sqssh-agent.
#[derive(Debug, Clone)]
pub enum AgentResponse {
    Ok,
    Keys { entries: Vec<AgentKeyEntry> },
    Seed { seed: Vec<u8> },
    Error { message: String },
}

#[derive(Debug, Clone)]
pub struct AgentKeyEntry {
    pub pubkey: Vec<u8>,
    pub comment: String,
}

impl AgentRequest {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::AddKey { seed, comment } => {
                let cb = comment.as_bytes();
                let mut buf = Vec::with_capacity(1 + 32 + 2 + cb.len());
                buf.push(AGENT_ADD_KEY);
                buf.extend_from_slice(seed);
                buf.extend_from_slice(&(cb.len() as u16).to_be_bytes());
                buf.extend_from_slice(cb);
                buf
            }
            Self::RemoveKey { pubkey } => {
                let mut buf = Vec::with_capacity(1 + 32);
                buf.push(AGENT_REMOVE_KEY);
                buf.extend_from_slice(pubkey);
                buf
            }
            Self::RemoveAll => vec![AGENT_REMOVE_ALL],
            Self::ListKeys => vec![AGENT_LIST_KEYS],
            Self::GetSeed { pubkey } => {
                let mut buf = Vec::with_capacity(1 + 32);
                buf.push(AGENT_GET_SEED);
                buf.extend_from_slice(pubkey);
                buf
            }
        }
    }

    pub fn decode(reader: &mut impl std::io::Read) -> Result<Self> {
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf)
            .map_err(|e| Error::Connection(format!("agent req type: {e}")))?;
        match type_buf[0] {
            AGENT_ADD_KEY => {
                let mut seed = [0u8; 32];
                reader.read_exact(&mut seed)
                    .map_err(|e| Error::Connection(format!("agent add seed: {e}")))?;
                let mut clen = [0u8; 2];
                reader.read_exact(&mut clen)
                    .map_err(|e| Error::Connection(format!("agent add comment len: {e}")))?;
                let cl = u16::from_be_bytes(clen) as usize;
                let mut cb = vec![0u8; cl];
                if cl > 0 {
                    reader.read_exact(&mut cb)
                        .map_err(|e| Error::Connection(format!("agent add comment: {e}")))?;
                }
                Ok(Self::AddKey {
                    seed: seed.to_vec(),
                    comment: String::from_utf8(cb).unwrap_or_default(),
                })
            }
            AGENT_REMOVE_KEY => {
                let mut pubkey = [0u8; 32];
                reader.read_exact(&mut pubkey)
                    .map_err(|e| Error::Connection(format!("agent remove pubkey: {e}")))?;
                Ok(Self::RemoveKey { pubkey: pubkey.to_vec() })
            }
            AGENT_REMOVE_ALL => Ok(Self::RemoveAll),
            AGENT_LIST_KEYS => Ok(Self::ListKeys),
            AGENT_GET_SEED => {
                let mut pubkey = [0u8; 32];
                reader.read_exact(&mut pubkey)
                    .map_err(|e| Error::Connection(format!("agent get seed pubkey: {e}")))?;
                Ok(Self::GetSeed { pubkey: pubkey.to_vec() })
            }
            other => Err(Error::Protocol(format!("unknown agent req: {other:#x}"))),
        }
    }

    pub async fn decode_async(recv: &mut (impl tokio::io::AsyncReadExt + Unpin)) -> Result<Self> {
        let mut type_buf = [0u8; 1];
        recv.read_exact(&mut type_buf).await
            .map_err(|e| Error::Connection(format!("agent req type: {e}")))?;
        match type_buf[0] {
            AGENT_ADD_KEY => {
                let mut seed = [0u8; 32];
                recv.read_exact(&mut seed).await
                    .map_err(|e| Error::Connection(format!("agent add seed: {e}")))?;
                let mut clen = [0u8; 2];
                recv.read_exact(&mut clen).await
                    .map_err(|e| Error::Connection(format!("agent add comment len: {e}")))?;
                let cl = u16::from_be_bytes(clen) as usize;
                let mut cb = vec![0u8; cl];
                if cl > 0 {
                    recv.read_exact(&mut cb).await
                        .map_err(|e| Error::Connection(format!("agent add comment: {e}")))?;
                }
                Ok(Self::AddKey {
                    seed: seed.to_vec(),
                    comment: String::from_utf8(cb).unwrap_or_default(),
                })
            }
            AGENT_REMOVE_KEY => {
                let mut pubkey = [0u8; 32];
                recv.read_exact(&mut pubkey).await
                    .map_err(|e| Error::Connection(format!("agent remove pubkey: {e}")))?;
                Ok(Self::RemoveKey { pubkey: pubkey.to_vec() })
            }
            AGENT_REMOVE_ALL => Ok(Self::RemoveAll),
            AGENT_LIST_KEYS => Ok(Self::ListKeys),
            AGENT_GET_SEED => {
                let mut pubkey = [0u8; 32];
                recv.read_exact(&mut pubkey).await
                    .map_err(|e| Error::Connection(format!("agent get seed pubkey: {e}")))?;
                Ok(Self::GetSeed { pubkey: pubkey.to_vec() })
            }
            other => Err(Error::Protocol(format!("unknown agent req: {other:#x}"))),
        }
    }
}

impl AgentResponse {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ok => vec![AGENT_RESP_OK],
            Self::Error { message } => {
                let mb = message.as_bytes();
                let mut buf = Vec::with_capacity(1 + 2 + mb.len());
                buf.push(AGENT_RESP_ERROR);
                buf.extend_from_slice(&(mb.len() as u16).to_be_bytes());
                buf.extend_from_slice(mb);
                buf
            }
            Self::Keys { entries } => {
                let mut buf = Vec::new();
                buf.push(AGENT_RESP_KEYS);
                buf.extend_from_slice(&(entries.len() as u32).to_be_bytes());
                for entry in entries {
                    buf.extend_from_slice(&entry.pubkey);
                    let cb = entry.comment.as_bytes();
                    buf.extend_from_slice(&(cb.len() as u16).to_be_bytes());
                    buf.extend_from_slice(cb);
                }
                buf
            }
            Self::Seed { seed } => {
                let mut buf = Vec::with_capacity(1 + 32);
                buf.push(AGENT_RESP_SEED);
                buf.extend_from_slice(seed);
                buf
            }
        }
    }

    pub fn decode(reader: &mut impl std::io::Read) -> Result<Self> {
        let mut type_buf = [0u8; 1];
        reader.read_exact(&mut type_buf)
            .map_err(|e| Error::Connection(format!("agent resp type: {e}")))?;
        match type_buf[0] {
            AGENT_RESP_OK => Ok(Self::Ok),
            AGENT_RESP_ERROR => {
                let mut mlen = [0u8; 2];
                reader.read_exact(&mut mlen)
                    .map_err(|e| Error::Connection(format!("agent error len: {e}")))?;
                let ml = u16::from_be_bytes(mlen) as usize;
                let mut mb = vec![0u8; ml];
                if ml > 0 {
                    reader.read_exact(&mut mb)
                        .map_err(|e| Error::Connection(format!("agent error msg: {e}")))?;
                }
                Ok(Self::Error { message: String::from_utf8(mb).unwrap_or_default() })
            }
            AGENT_RESP_KEYS => {
                let mut count_buf = [0u8; 4];
                reader.read_exact(&mut count_buf)
                    .map_err(|e| Error::Connection(format!("agent keys count: {e}")))?;
                let count = u32::from_be_bytes(count_buf) as usize;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let mut pk = [0u8; 32];
                    reader.read_exact(&mut pk)
                        .map_err(|e| Error::Connection(format!("agent key pubkey: {e}")))?;
                    let mut clen = [0u8; 2];
                    reader.read_exact(&mut clen)
                        .map_err(|e| Error::Connection(format!("agent key comment len: {e}")))?;
                    let cl = u16::from_be_bytes(clen) as usize;
                    let mut cb = vec![0u8; cl];
                    if cl > 0 {
                        reader.read_exact(&mut cb)
                            .map_err(|e| Error::Connection(format!("agent key comment: {e}")))?;
                    }
                    entries.push(AgentKeyEntry {
                        pubkey: pk.to_vec(),
                        comment: String::from_utf8(cb).unwrap_or_default(),
                    });
                }
                Ok(Self::Keys { entries })
            }
            AGENT_RESP_SEED => {
                let mut seed = [0u8; 32];
                reader.read_exact(&mut seed)
                    .map_err(|e| Error::Connection(format!("agent seed: {e}")))?;
                Ok(Self::Seed { seed: seed.to_vec() })
            }
            other => Err(Error::Protocol(format!("unknown agent resp: {other:#x}"))),
        }
    }
}
