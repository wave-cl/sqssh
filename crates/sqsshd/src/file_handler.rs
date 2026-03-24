use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sqssh_core::protocol::{ChannelMsg, ManifestEntry};
use sqssh_core::stream::Channel;

/// Maximum path component length to prevent abuse.
const MAX_PATH_LEN: usize = 4096;

/// Chunk size for file data transfers (64 KB).
const CHUNK_SIZE: usize = 64 * 1024;

/// Validate a path: reject traversal, ensure it's within allowed scope.
fn validate_path(base: &Path, relative: &str) -> Result<PathBuf, String> {
    if relative.len() > MAX_PATH_LEN {
        return Err("path too long".into());
    }
    if relative.contains("..") {
        return Err("path traversal not allowed".into());
    }

    // Expand ~ and ~/ to user's home directory
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

/// Handle a file upload (client → server).
pub async fn handle_upload(
    channel: &mut Channel,
    username: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (uid, gid, home, _shell) = super::pty_handler::lookup_user(username)?;

    let target = validate_path(Path::new(&home), path)
        .map_err(|e| format!("invalid path: {e}"))?;

    // Receive file header
    let msg = channel.recv().await?;
    let (file_path, size, mode, mtime, atime) = match msg {
        ChannelMsg::FileHeader {
            size, mode, mtime, atime, ..
        } => {
            // Use the path from the channel type (already validated)
            (target.clone(), size, mode, mtime, atime)
        }
        ChannelMsg::FileManifest { entries } => {
            return handle_upload_manifest(channel, username, uid, gid, &target, entries).await;
        }
        other => {
            channel
                .send(&ChannelMsg::FileResult {
                    success: false,
                    message: format!("expected FileHeader or FileManifest, got {other:?}"),
                })
                .await?;
            return Ok(());
        }
    };

    // Create parent directories
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    match write_file_from_channel(channel, &file_path, size, mode, mtime, atime, uid, gid).await {
        Ok(()) => {
            channel
                .send(&ChannelMsg::FileResult {
                    success: true,
                    message: String::new(),
                })
                .await?;
        }
        Err(e) => {
            channel
                .send(&ChannelMsg::FileResult {
                    success: false,
                    message: e.to_string(),
                })
                .await?;
        }
    }

    Ok(())
}

async fn write_file_from_channel(
    channel: &mut Channel,
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

    loop {
        match channel.recv().await? {
            ChannelMsg::Data { payload } => {
                file.write_all(&payload)?;
                written += payload.len() as u64;
            }
            ChannelMsg::Eof => break,
            other => {
                return Err(format!("unexpected message during upload: {other:?}").into());
            }
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
        } else {
            tracing::debug!("set timestamps for {}: mtime={mtime}", path.display());
        }
    }

    Ok(())
}

/// Handle a file download (server → client).
pub async fn handle_download(
    channel: &mut Channel,
    username: &str,
    path: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_uid, _gid, home, _shell) = super::pty_handler::lookup_user(username)?;

    let source = validate_path(Path::new(&home), path)
        .map_err(|e| format!("invalid path: {e}"))?;

    // Follow symlinks for the source check
    let meta = std::fs::metadata(&source)?;
    if meta.is_dir() {
        let entries = walk_directory(&source, &source)?;
        channel
            .send(&ChannelMsg::FileManifest { entries })
            .await?;
        return Ok(());
    }

    send_file(channel, &source).await
}

async fn send_file(
    channel: &mut Channel,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Read;

    // Follow symlinks
    let meta = std::fs::metadata(path)?;
    let size = meta.len();
    let mode = meta.mode();
    let mtime = meta.mtime() as u64;
    let atime = meta.atime() as u64;
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    channel
        .send(&ChannelMsg::FileHeader {
            path: filename,
            size,
            mode,
            mtime,
            atime,
        })
        .await?;

    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; CHUNK_SIZE];

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        channel
            .send(&ChannelMsg::Data {
                payload: buf[..n].to_vec(),
            })
            .await?;
    }

    channel.send(&ChannelMsg::Eof).await?;

    match channel.recv().await? {
        ChannelMsg::FileResult { success, message } => {
            if !success {
                tracing::warn!("client reported error for {}: {message}", path.display());
            }
        }
        _ => {}
    }

    Ok(())
}

/// Handle a manifest-based upload (recursive directory upload).
async fn handle_upload_manifest(
    channel: &mut Channel,
    _username: &str,
    uid: u32,
    gid: u32,
    target: &Path,
    entries: Vec<ManifestEntry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for entry in &entries {
        if entry.is_dir {
            let dir_path = target.join(&entry.path);
            std::fs::create_dir_all(&dir_path)?;
            std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(entry.mode))?;
            let c_path = std::ffi::CString::new(dir_path.to_string_lossy().as_bytes())?;
            unsafe {
                libc::chown(c_path.as_ptr(), uid, gid);
            }
        }
    }

    channel
        .send(&ChannelMsg::FileResult {
            success: true,
            message: format!("{} entries", entries.len()),
        })
        .await?;

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
        // Follow symlinks
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
