use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Maximum message payload size (16 MB).
pub const MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

/// ALPN protocol identifier.
pub const ALPN: &[u8] = b"sqssh/1";

/// Default sqssh port (UDP).
pub const DEFAULT_PORT: u16 = 22;

// -- Message type discriminants --

const MSG_AUTH_REQUEST: u8 = 0x01;
const MSG_AUTH_SUCCESS: u8 = 0x02;
const MSG_AUTH_FAILURE: u8 = 0x03;
const MSG_TCPIP_FORWARD_REQUEST: u8 = 0x10;
const MSG_TCPIP_FORWARD_SUCCESS: u8 = 0x11;
const MSG_CANCEL_TCPIP_FORWARD: u8 = 0x12;
const MSG_UDP_FORWARD_REQUEST: u8 = 0x13;
const MSG_CANCEL_UDP_FORWARD: u8 = 0x14;
const MSG_DISCONNECT: u8 = 0x20;

const MSG_CHANNEL_OPEN: u8 = 0x30;
const MSG_CHANNEL_OPEN_CONFIRM: u8 = 0x31;
const MSG_CHANNEL_OPEN_FAILURE: u8 = 0x32;
const MSG_PTY_REQUEST: u8 = 0x40;
const MSG_PTY_SUCCESS: u8 = 0x41;
const MSG_SHELL_REQUEST: u8 = 0x42;
const MSG_EXEC_REQUEST: u8 = 0x43;
const MSG_SUBSYSTEM_REQUEST: u8 = 0x44;
const MSG_DATA: u8 = 0x50;
const MSG_EXTENDED_DATA: u8 = 0x51;
const MSG_WINDOW_CHANGE: u8 = 0x60;
const MSG_SIGNAL: u8 = 0x61;
const MSG_EXIT_STATUS: u8 = 0x62;
const MSG_EXIT_SIGNAL: u8 = 0x63;
const MSG_FILE_HEADER: u8 = 0x80;
const MSG_FILE_RESULT: u8 = 0x81;
const MSG_FILE_MANIFEST: u8 = 0x82;
const MSG_SFTP_LIST_DIR: u8 = 0x90;
const MSG_SFTP_STAT: u8 = 0x91;
const MSG_SFTP_MKDIR: u8 = 0x92;
const MSG_SFTP_REMOVE: u8 = 0x93;
const MSG_SFTP_RENAME: u8 = 0x94;
const MSG_SFTP_REALPATH: u8 = 0x95;
const MSG_SFTP_DIR_LISTING: u8 = 0x96;
const MSG_SFTP_STAT_RESULT: u8 = 0x97;
const MSG_SFTP_OK: u8 = 0x98;
const MSG_SFTP_ERROR: u8 = 0x99;
const MSG_EOF: u8 = 0x70;
const MSG_CLOSE: u8 = 0x71;

// -- Control channel messages (stream 0) --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMsg {
    AuthRequest {
        username: String,
        pubkey: Vec<u8>,
    },
    AuthSuccess,
    AuthFailure {
        message: String,
    },
    TcpipForwardRequest {
        bind_addr: String,
        bind_port: u16,
    },
    TcpipForwardSuccess {
        bound_port: u16,
    },
    CancelTcpipForward {
        bind_addr: String,
        bind_port: u16,
    },
    UdpForwardRequest {
        bind_addr: String,
        bind_port: u16,
    },
    CancelUdpForward {
        bind_addr: String,
        bind_port: u16,
    },
    Disconnect {
        reason: u32,
        description: String,
    },
}

// -- Channel messages (per-channel bidi streams) --

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelType {
    Session,
    DirectTcpip {
        host: String,
        port: u16,
        originator_host: String,
        originator_port: u16,
    },
    DirectUdp {
        host: String,
        port: u16,
    },
    FileTransfer {
        direction: TransferDirection,
        path: String,
    },
    /// Raw download: server sends file data on uni streams.
    /// Client opens bidi channel, server responds with manifest or single-file signal.
    RawDownload {
        path: String,
        /// Number of parallel streams for single-file chunked transfer.
        jobs: u32,
    },
    Sftp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelMsg {
    ChannelOpen {
        channel_type: ChannelType,
    },
    ChannelOpenConfirm,
    ChannelOpenFailure {
        reason: u32,
        description: String,
    },
    PtyRequest {
        term: String,
        cols: u32,
        rows: u32,
    },
    PtySuccess,
    ShellRequest,
    ExecRequest {
        command: String,
    },
    SubsystemRequest {
        name: String,
    },
    Data {
        payload: Vec<u8>,
    },
    ExtendedData {
        data_type: u32,
        payload: Vec<u8>,
    },
    WindowChange {
        cols: u32,
        rows: u32,
    },
    Signal {
        name: String,
    },
    ExitStatus {
        code: u32,
    },
    ExitSignal {
        signal: String,
        core_dumped: bool,
        message: String,
    },
    FileHeader {
        path: String,
        size: u64,
        mode: u32,
        /// Modification time (seconds since epoch). 0 = not preserved.
        mtime: u64,
        /// Access time (seconds since epoch). 0 = not preserved.
        atime: u64,
    },
    FileResult {
        success: bool,
        message: String,
    },
    FileManifest {
        entries: Vec<ManifestEntry>,
    },
    // -- SFTP interactive commands --
    SftpListDir {
        path: String,
    },
    SftpStat {
        path: String,
    },
    SftpMkdir {
        path: String,
        mode: u32,
    },
    SftpRemove {
        path: String,
    },
    SftpRename {
        old_path: String,
        new_path: String,
    },
    SftpRealpath {
        path: String,
    },
    SftpDirListing {
        entries: Vec<ManifestEntry>,
    },
    SftpStatResult {
        path: String,
        size: u64,
        mode: u32,
        mtime: u64,
        atime: u64,
        is_dir: bool,
    },
    SftpOk {
        message: String,
    },
    SftpError {
        message: String,
    },
    Eof,
    Close,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub is_dir: bool,
    pub mtime: u64,
    pub atime: u64,
}

// -- Wire encoding/decoding --

impl ControlMsg {
    fn msg_type(&self) -> u8 {
        match self {
            Self::AuthRequest { .. } => MSG_AUTH_REQUEST,
            Self::AuthSuccess => MSG_AUTH_SUCCESS,
            Self::AuthFailure { .. } => MSG_AUTH_FAILURE,
            Self::TcpipForwardRequest { .. } => MSG_TCPIP_FORWARD_REQUEST,
            Self::TcpipForwardSuccess { .. } => MSG_TCPIP_FORWARD_SUCCESS,
            Self::CancelTcpipForward { .. } => MSG_CANCEL_TCPIP_FORWARD,
            Self::UdpForwardRequest { .. } => MSG_UDP_FORWARD_REQUEST,
            Self::CancelUdpForward { .. } => MSG_CANCEL_UDP_FORWARD,
            Self::Disconnect { .. } => MSG_DISCONNECT,
        }
    }

    /// Encode to wire format: [4-byte length][1-byte type][msgpack payload]
    pub fn encode(&self) -> Result<Bytes> {
        let payload =
            rmp_serde::to_vec(self).map_err(|e| Error::Serialization(e.to_string()))?;
        let total_len = 1 + payload.len();
        let mut buf = BytesMut::with_capacity(4 + total_len);
        buf.put_u32(total_len as u32);
        buf.put_u8(self.msg_type());
        buf.put_slice(&payload);
        Ok(buf.freeze())
    }

    /// Decode from wire format (after length prefix has been read).
    pub fn decode(msg_type: u8, payload: &[u8]) -> Result<Self> {
        let msg: Self =
            rmp_serde::from_slice(payload).map_err(|e| Error::Serialization(e.to_string()))?;

        // Verify the decoded variant matches the wire type
        if msg.msg_type() != msg_type {
            return Err(Error::Protocol(format!(
                "message type mismatch: wire={msg_type:#x}, decoded={:#x}",
                msg.msg_type()
            )));
        }

        Ok(msg)
    }
}

impl ChannelMsg {
    fn msg_type(&self) -> u8 {
        match self {
            Self::ChannelOpen { .. } => MSG_CHANNEL_OPEN,
            Self::ChannelOpenConfirm => MSG_CHANNEL_OPEN_CONFIRM,
            Self::ChannelOpenFailure { .. } => MSG_CHANNEL_OPEN_FAILURE,
            Self::PtyRequest { .. } => MSG_PTY_REQUEST,
            Self::PtySuccess => MSG_PTY_SUCCESS,
            Self::ShellRequest => MSG_SHELL_REQUEST,
            Self::ExecRequest { .. } => MSG_EXEC_REQUEST,
            Self::SubsystemRequest { .. } => MSG_SUBSYSTEM_REQUEST,
            Self::Data { .. } => MSG_DATA,
            Self::ExtendedData { .. } => MSG_EXTENDED_DATA,
            Self::WindowChange { .. } => MSG_WINDOW_CHANGE,
            Self::Signal { .. } => MSG_SIGNAL,
            Self::ExitStatus { .. } => MSG_EXIT_STATUS,
            Self::ExitSignal { .. } => MSG_EXIT_SIGNAL,
            Self::FileHeader { .. } => MSG_FILE_HEADER,
            Self::FileResult { .. } => MSG_FILE_RESULT,
            Self::FileManifest { .. } => MSG_FILE_MANIFEST,
            Self::SftpListDir { .. } => MSG_SFTP_LIST_DIR,
            Self::SftpStat { .. } => MSG_SFTP_STAT,
            Self::SftpMkdir { .. } => MSG_SFTP_MKDIR,
            Self::SftpRemove { .. } => MSG_SFTP_REMOVE,
            Self::SftpRename { .. } => MSG_SFTP_RENAME,
            Self::SftpRealpath { .. } => MSG_SFTP_REALPATH,
            Self::SftpDirListing { .. } => MSG_SFTP_DIR_LISTING,
            Self::SftpStatResult { .. } => MSG_SFTP_STAT_RESULT,
            Self::SftpOk { .. } => MSG_SFTP_OK,
            Self::SftpError { .. } => MSG_SFTP_ERROR,
            Self::Eof => MSG_EOF,
            Self::Close => MSG_CLOSE,
        }
    }

    /// Encode to wire format.
    pub fn encode(&self) -> Result<Bytes> {
        let payload =
            rmp_serde::to_vec(self).map_err(|e| Error::Serialization(e.to_string()))?;
        let total_len = 1 + payload.len();
        let mut buf = BytesMut::with_capacity(4 + total_len);
        buf.put_u32(total_len as u32);
        buf.put_u8(self.msg_type());
        buf.put_slice(&payload);
        Ok(buf.freeze())
    }

    /// Decode from wire format (after length prefix has been read).
    pub fn decode(msg_type: u8, payload: &[u8]) -> Result<Self> {
        let msg: Self =
            rmp_serde::from_slice(payload).map_err(|e| Error::Serialization(e.to_string()))?;

        if msg.msg_type() != msg_type {
            return Err(Error::Protocol(format!(
                "message type mismatch: wire={msg_type:#x}, decoded={:#x}",
                msg.msg_type()
            )));
        }

        Ok(msg)
    }
}

/// Read a single framed message from a QUIC receive stream.
/// Returns (msg_type, payload_bytes).
pub async fn read_frame(
    recv: &mut quinn::RecvStream,
) -> Result<(u8, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| Error::Connection(format!("failed to read frame length: {e}")))?;
    let len = u32::from_be_bytes(len_buf);

    if len == 0 {
        return Err(Error::Protocol("zero-length frame".into()));
    }
    if len > MAX_MESSAGE_SIZE {
        return Err(Error::Protocol(format!(
            "frame too large: {len} > {MAX_MESSAGE_SIZE}"
        )));
    }

    let mut data = vec![0u8; len as usize];
    recv.read_exact(&mut data)
        .await
        .map_err(|e| Error::Connection(format!("failed to read frame data: {e}")))?;

    let msg_type = data[0];
    let payload = data[1..].to_vec();

    Ok((msg_type, payload))
}

/// Write a pre-encoded frame to a QUIC send stream.
pub async fn write_frame(
    send: &mut quinn::SendStream,
    data: &[u8],
) -> Result<()> {
    send.write_all(data)
        .await
        .map_err(|e| Error::Connection(format!("failed to write frame: {e}")))?;
    Ok(())
}

/// Read a ControlMsg from a QUIC receive stream.
pub async fn read_control_msg(recv: &mut quinn::RecvStream) -> Result<ControlMsg> {
    let (msg_type, payload) = read_frame(recv).await?;
    ControlMsg::decode(msg_type, &payload)
}

/// Write a ControlMsg to a QUIC send stream.
pub async fn write_control_msg(
    send: &mut quinn::SendStream,
    msg: &ControlMsg,
) -> Result<()> {
    let data = msg.encode()?;
    write_frame(send, &data).await
}

/// Read a ChannelMsg from a QUIC receive stream.
pub async fn read_channel_msg(recv: &mut quinn::RecvStream) -> Result<ChannelMsg> {
    let (msg_type, payload) = read_frame(recv).await?;
    ChannelMsg::decode(msg_type, &payload)
}

/// Write a ChannelMsg to a QUIC send stream.
pub async fn write_channel_msg(
    send: &mut quinn::SendStream,
    msg: &ChannelMsg,
) -> Result<()> {
    let data = msg.encode()?;
    write_frame(send, &data).await
}

// -- Control socket protocol (Unix domain socket, sqsshctl ↔ sqsshd) --

/// Request from sqsshctl to sqsshd over the control socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CtlRequest {
    /// Reload the calling user's authorized_keys.
    ReloadKeys,
    /// Reload all users' authorized_keys (root only).
    ReloadAllKeys,
}

/// Response from sqsshd to sqsshctl over the control socket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CtlResponse {
    Ok { message: String },
    Error { message: String },
}

/// Encode a control socket message as length-prefixed msgpack.
pub fn ctl_encode<T: Serialize>(msg: &T) -> Result<Vec<u8>> {
    let payload = rmp_serde::to_vec(msg)
        .map_err(|e| Error::Serialization(e.to_string()))?;
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Decode a control socket message from a blocking reader.
pub fn ctl_decode<T: for<'de> Deserialize<'de>>(reader: &mut impl std::io::Read) -> Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)
        .map_err(|e| Error::Connection(format!("failed to read ctl frame: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE as usize {
        return Err(Error::Protocol("ctl frame too large".into()));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)
        .map_err(|e| Error::Connection(format!("failed to read ctl payload: {e}")))?;
    rmp_serde::from_slice(&payload)
        .map_err(|e| Error::Serialization(e.to_string()))
}

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

/// Encode a download request on a metadata bidi stream.
pub fn encode_download_request(path: &str) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    let mut buf = Vec::with_capacity(1 + 2 + path_bytes.len());
    buf.push(RAW_DOWNLOAD_REQUEST);
    buf.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(path_bytes);
    buf
}

/// Encode a manifest request on a metadata bidi stream.
pub fn encode_manifest_request(path: &str) -> Vec<u8> {
    let path_bytes = path.as_bytes();
    let mut buf = Vec::with_capacity(1 + 2 + path_bytes.len());
    buf.push(RAW_MANIFEST_REQUEST);
    buf.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(path_bytes);
    buf
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

// -- Agent protocol (Unix domain socket, sqssh-agent) --

/// Request from sqssh-add or client to sqssh-agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentRequest {
    /// Add a key to the agent. Seed is the 32-byte Ed25519 private key seed.
    AddKey { seed: Vec<u8>, comment: String },
    /// Remove a specific key by its public key bytes.
    RemoveKey { pubkey: Vec<u8> },
    /// Remove all keys.
    RemoveAll,
    /// List all loaded keys.
    ListKeys,
    /// Get the private key seed for QUIC handshake (returns seed bytes).
    GetSeed { pubkey: Vec<u8> },
}

/// Response from sqssh-agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentResponse {
    Ok,
    Keys { entries: Vec<AgentKeyEntry> },
    Seed { seed: Vec<u8> },
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentKeyEntry {
    pub pubkey: Vec<u8>,
    pub comment: String,
}
