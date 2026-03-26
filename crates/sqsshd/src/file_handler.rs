use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sqssh_core::protocol::{
    self, ManifestEntry, RawFileHeader, RAW_CHUNK_SIZE, RAW_DOWNLOAD_DATA,
};

/// Maximum path component length to prevent abuse.
const MAX_PATH_LEN: usize = 4096;

/// Validate a path: reject traversal, ensure it's within allowed scope.
fn validate_path(base: &Path, relative: &str) -> Result<PathBuf, String> {
    if relative.len() > MAX_PATH_LEN {
        return Err("path too long".into());
    }
    if relative.contains("..") {
        return Err("path traversal not allowed".into());
    }

    let expanded = if relative == "~" || relative == "~/" {
        base.to_path_buf()
    } else if let Some(rest) = relative.strip_prefix("~/") {
        base.join(rest)
    } else if relative.starts_with('/') {
        PathBuf::from(relative)
    } else {
        base.join(relative)
    };

    Ok(expanded)
}

/// Handle an incoming raw upload uni stream (client → server).
pub async fn handle_raw_upload(
    mut recv: quinn::RecvStream,
    username: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (uid, gid, home, _shell) = super::pty_handler::lookup_user(username)?;

    // Type byte already consumed by caller. Read header.
    let header = RawFileHeader::decode(&mut recv).await?;

    let target = validate_path(Path::new(&home), &header.path)
        .map_err(|e| format!("invalid path: {e}"))?;

    // Create parent directories
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    // Stream raw bytes directly to file
    write_file_from_stream(&mut recv, &target, header.size, header.mode, header.mtime, header.atime, uid, gid).await?;

    tracing::debug!(path = %target.display(), size = header.size, "upload complete");
    Ok(())
}

/// Write file data from a raw QUIC recv stream directly to disk.
async fn write_file_from_stream(
    recv: &mut quinn::RecvStream,
    path: &Path,
    expected_size: u64,
    mode: u32,
    mtime: u64,
    atime: u64,
    uid: u32,
    gid: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Write;

    let mut file = std::fs::File::create(path)?;
    let mut written: u64 = 0;
    let mut buf = vec![0u8; RAW_CHUNK_SIZE];

    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                file.write_all(&buf[..n])?;
                written += n as u64;
            }
            Ok(None) => break, // FIN = EOF
            Err(e) => return Err(format!("read error: {e}").into()),
        }
    }

    file.flush()?;
    drop(file);

    if written != expected_size {
        tracing::warn!(
            "size mismatch for {}: expected {expected_size}, got {written}",
            path.display()
        );
    }

    // Set permissions and ownership
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())?;
    unsafe {
        libc::chown(c_path.as_ptr(), uid, gid);
    }

    // Preserve timestamps if provided
    if mtime > 0 {
        let times = [
            libc::timeval {
                tv_sec: atime as libc::time_t,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: mtime as libc::time_t,
                tv_usec: 0,
            },
        ];
        let ret = unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!("utimes failed for {}: {err}", path.display());
        }
    }

    Ok(())
}

/// Receive a raw file from a uni stream and write to disk.
/// Used by SFTP put handler.
pub async fn receive_raw_file(
    recv: &mut quinn::RecvStream,
    path: &Path,
    size: u64,
    mode: u32,
    mtime: u64,
    atime: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let mut file = std::fs::File::create(path)?;
    let mut written: u64 = 0;
    let mut buf = vec![0u8; RAW_CHUNK_SIZE];

    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                file.write_all(&buf[..n])?;
                written += n as u64;
            }
            Ok(None) => break,
            Err(e) => return Err(format!("read error: {e}").into()),
        }
    }

    file.flush()?;
    drop(file);

    if written != size {
        tracing::warn!("size mismatch for {}: expected {size}, got {written}", path.display());
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;

    if mtime > 0 {
        let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())?;
        let times = [
            libc::timeval { tv_sec: atime as libc::time_t, tv_usec: 0 },
            libc::timeval { tv_sec: mtime as libc::time_t, tv_usec: 0 },
        ];
        unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()); }
    }

    Ok(())
}

/// Send a file on a raw unidirectional QUIC stream (server → client).
async fn send_file_raw(
    conn: quinn::Connection,
    path: PathBuf,
    relative_path: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let meta = std::fs::metadata(&path)?;
    let header = RawFileHeader {
        path: relative_path,
        size: meta.len(),
        mode: meta.mode(),
        mtime: meta.mtime() as u64,
        atime: meta.atime() as u64,
    };

    let mut send = conn.open_uni().await
        .map_err(|e| format!("failed to open download stream: {e}"))?;

    // Write header
    send.write_all(&header.encode_download()).await
        .map_err(|e| format!("failed to write download header: {e}"))?;

    // Stream raw file data using async I/O to avoid blocking tokio
    let mut file = tokio::fs::File::open(&path).await?;
    let mut buf = vec![0u8; RAW_CHUNK_SIZE];

    loop {
        let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
        if n == 0 {
            break;
        }
        send.write_all(&buf[..n]).await
            .map_err(|e| format!("write error: {e}"))?;
    }

    // FIN = EOF
    send.finish()
        .map_err(|e| format!("finish error: {e}"))?;

    Ok(())
}

/// Send a chunk of a file on a raw uni stream (server → client).
async fn send_file_chunk_raw(
    conn: &quinn::Connection,
    file: &std::fs::File,
    path: &str,
    file_size: u64,
    mode: u32,
    mtime: u64,
    atime: u64,
    offset: u64,
    length: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::FileExt;

    let header = protocol::RawChunkHeader {
        path: path.to_string(),
        file_size,
        mode,
        mtime,
        atime,
        offset,
        chunk_length: length,
    };

    let mut send = conn.open_uni().await
        .map_err(|e| format!("failed to open chunk download stream: {e}"))?;

    send.write_all(&header.encode_download()).await
        .map_err(|e| format!("chunk header write: {e}"))?;

    let mut buf = vec![0u8; RAW_CHUNK_SIZE];
    let mut sent: u64 = 0;

    while sent < length {
        let to_read = std::cmp::min(RAW_CHUNK_SIZE as u64, length - sent) as usize;
        let n = file.read_at(&mut buf[..to_read], offset + sent)
            .map_err(|e| format!("read_at: {e}"))?;
        if n == 0 { break; }

        send.write_all(&buf[..n]).await
            .map_err(|e| format!("chunk write: {e}"))?;
        sent += n as u64;
    }

    send.finish().map_err(|e| format!("finish: {e}"))?;
    Ok(())
}

/// Walk a directory and build a manifest. Follows symlinks.
fn walk_directory(
    root: &Path,
    base: &Path,
) -> Result<Vec<ManifestEntry>, Box<dyn std::error::Error + Send + Sync>> {
    let mut entries = Vec::new();

    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let meta = std::fs::metadata(entry.path())?;
        let relative = entry
            .path()
            .strip_prefix(base)
            .unwrap_or(&entry.path())
            .to_string_lossy()
            .to_string();

        if meta.is_dir() {
            entries.push(ManifestEntry {
                path: relative.clone(),
                size: 0,
                mode: meta.mode(),
                is_dir: true,
                mtime: meta.mtime() as u64,
                atime: meta.atime() as u64,
            });
            let sub = walk_directory(&entry.path(), base)?;
            entries.extend(sub);
        } else if meta.is_file() {
            entries.push(ManifestEntry {
                path: relative,
                size: meta.len(),
                mode: meta.mode(),
                is_dir: false,
                mtime: meta.mtime() as u64,
                atime: meta.atime() as u64,
            });
        }
    }

    Ok(entries)
}

/// Handle a chunked upload uni stream (client → server, with offset).
pub async fn handle_raw_upload_chunk(
    mut recv: quinn::RecvStream,
    username: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::FileExt;

    let (_uid, _gid, home, _shell) = super::pty_handler::lookup_user(username)?;

    let header = protocol::RawChunkHeader::decode(&mut recv).await?;

    let target = validate_path(Path::new(&home), &header.path)
        .map_err(|e| format!("invalid path: {e}"))?;

    // Create parent directories and pre-create file if needed
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    // Open file for writing at offset (create if not exists, don't truncate)
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open(&target)?;

    // Pre-allocate as sparse file to avoid pwrite filling gaps with zeros
    file.set_len(header.file_size)?;

    tracing::info!(
        path = %target.display(),
        offset = header.offset,
        chunk_length = header.chunk_length,
        file_size = header.file_size,
        "starting chunk write"
    );

    // Write at offset using pwrite
    let mut buf = vec![0u8; RAW_CHUNK_SIZE];
    let mut written: u64 = 0;

    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                file.write_at(&buf[..n], header.offset + written)?;
                written += n as u64;
            }
            Ok(None) => break,
            Err(e) => return Err(format!("chunk read error: {e}").into()),
        }
    }

    tracing::debug!(
        path = %target.display(),
        offset = header.offset,
        length = written,
        "chunk upload complete"
    );

    // Set permissions after last chunk (race-safe: idempotent)
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(header.mode))?;
    let c_path = std::ffi::CString::new(target.to_string_lossy().as_bytes())?;
    let (uid, gid, _, _) = super::pty_handler::lookup_user(username)?;
    unsafe { libc::chown(c_path.as_ptr(), uid, gid); }

    if header.mtime > 0 {
        let times = [
            libc::timeval { tv_sec: header.atime as libc::time_t, tv_usec: 0 },
            libc::timeval { tv_sec: header.mtime as libc::time_t, tv_usec: 0 },
        ];
        unsafe { libc::utimes(c_path.as_ptr(), times.as_ptr()); }
    }

    Ok(())
}

/// Handle a raw download request via bidi streams + uni data streams.
/// The type byte and path+jobs have already been consumed by the dispatcher.
pub async fn handle_raw_download(
    conn: &quinn::Connection,
    mut send: quinn::SendStream,
    _recv: quinn::RecvStream,
    username: &str,
    path: &str,
    jobs: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_uid, _gid, home, _shell) = super::pty_handler::lookup_user(username)?;

    let source = validate_path(Path::new(&home), path)
        .map_err(|e| format!("invalid path: {e}"))?;

    let meta = match std::fs::metadata(&source) {
        Ok(m) => m,
        Err(e) => {
            let result = protocol::encode_transfer_result(false, &e.to_string());
            send.write_all(&result).await.ok();
            return Ok(());
        }
    };

    if meta.is_dir() {
        // Send manifest on bidi send
        let entries = walk_directory(&source, &source)?;
        let manifest = protocol::encode_manifest_response(&entries);
        send.write_all(&manifest).await
            .map_err(|e| format!("failed to send manifest: {e}"))?;

        // Send each file on a separate uni stream, limit concurrency to avoid
        // exceeding QUIC max_concurrent_uni_streams
        let file_entries: Vec<_> = entries.iter().filter(|e| !e.is_dir).collect();
        let sem = Arc::new(tokio::sync::Semaphore::new(std::cmp::min(jobs as usize, 64)));
        let mut handles = Vec::with_capacity(file_entries.len());
        for entry in file_entries {
            let file_path = source.join(&entry.path);
            let rel_path = entry.path.clone();
            let conn = conn.clone();
            let sem = sem.clone();
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                send_file_raw(conn, file_path, rel_path).await
            }));
        }
        for handle in handles {
            handle.await.map_err(|e| format!("task join error: {e}"))??;
        }
    } else if jobs > 1 {
        // Single file, chunked across multiple uni streams
        let file_size = meta.len();
        let filename = source.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // Signal chunked download on bidi
        let signal = [protocol::RAW_DOWNLOAD_CHUNK];
        send.write_all(&signal).await
            .map_err(|e| format!("failed to send chunk signal: {e}"))?;

        // Send first chunk header on bidi for file metadata
        let first_header = protocol::RawChunkHeader {
            path: filename.clone(),
            file_size,
            mode: meta.mode(),
            mtime: meta.mtime() as u64,
            atime: meta.atime() as u64,
            offset: 0,
            chunk_length: 0, // metadata only
        };
        // Encode without type byte (type already sent)
        let mut meta_buf = Vec::new();
        let path_bytes = first_header.path.as_bytes();
        meta_buf.extend_from_slice(&(path_bytes.len() as u16).to_be_bytes());
        meta_buf.extend_from_slice(path_bytes);
        meta_buf.extend_from_slice(&first_header.file_size.to_be_bytes());
        meta_buf.extend_from_slice(&first_header.mode.to_be_bytes());
        meta_buf.extend_from_slice(&first_header.mtime.to_be_bytes());
        meta_buf.extend_from_slice(&first_header.atime.to_be_bytes());
        meta_buf.extend_from_slice(&first_header.offset.to_be_bytes());
        meta_buf.extend_from_slice(&first_header.chunk_length.to_be_bytes());
        send.write_all(&meta_buf).await
            .map_err(|e| format!("chunk metadata: {e}"))?;

        // Open j uni streams, each sending a chunk
        let chunk_size = file_size / jobs as u64;
        let file = Arc::new(std::fs::File::open(&source)?);

        let mut handles = Vec::new();
        for i in 0..jobs {
            let conn = conn.clone();
            let file = file.clone();
            let fname = filename.clone();
            let mode = meta.mode();
            let mtime = meta.mtime() as u64;
            let atime = meta.atime() as u64;

            let offset = i as u64 * chunk_size;
            let length = if i == jobs - 1 { file_size - offset } else { chunk_size };

            let handle = tokio::spawn(async move {
                send_file_chunk_raw(&conn, &file, &fname, file_size, mode, mtime, atime, offset, length).await
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await??;
        }
    } else {
        // Single file, single stream
        let signal = [RAW_DOWNLOAD_DATA];
        send.write_all(&signal).await
            .map_err(|e| format!("failed to send signal: {e}"))?;

        let filename = source
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        send_file_raw(conn.clone(), source, filename).await?;
    }

    Ok(())
}

