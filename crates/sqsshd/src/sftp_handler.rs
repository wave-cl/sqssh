use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sqssh_core::protocol::{ChannelMsg, ManifestEntry};
use sqssh_core::stream::Channel;

/// Maximum path length.
const MAX_PATH_LEN: usize = 4096;

/// Handle an interactive SFTP session.
pub async fn handle_sftp(
    channel: &mut Channel,
    username: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_uid, _gid, home, _shell) = super::pty_handler::lookup_user(username)?;
    let mut cwd = PathBuf::from(&home);

    tracing::info!(user = %username, "sftp session started");

    loop {
        let msg = match channel.recv().await {
            Ok(m) => m,
            Err(_) => break,
        };

        match msg {
            ChannelMsg::SftpListDir { path } => {
                let target = resolve_path(&cwd, &home, &path);
                match list_dir(&target) {
                    Ok(entries) => {
                        channel.send(&ChannelMsg::SftpDirListing { entries }).await?;
                    }
                    Err(e) => {
                        channel
                            .send(&ChannelMsg::SftpError {
                                message: e.to_string(),
                            })
                            .await?;
                    }
                }
            }

            ChannelMsg::SftpStat { path } => {
                let target = resolve_path(&cwd, &home, &path);
                match stat_path(&target) {
                    Ok(result) => {
                        channel.send(&result).await?;
                    }
                    Err(e) => {
                        channel
                            .send(&ChannelMsg::SftpError {
                                message: e.to_string(),
                            })
                            .await?;
                    }
                }
            }

            ChannelMsg::SftpMkdir { path, mode } => {
                let target = resolve_path(&cwd, &home, &path);
                match std::fs::create_dir(&target) {
                    Ok(()) => {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode))
                            .ok();
                        channel
                            .send(&ChannelMsg::SftpOk {
                                message: format!("created {}", target.display()),
                            })
                            .await?;
                    }
                    Err(e) => {
                        channel
                            .send(&ChannelMsg::SftpError {
                                message: e.to_string(),
                            })
                            .await?;
                    }
                }
            }

            ChannelMsg::SftpRemove { path } => {
                let target = resolve_path(&cwd, &home, &path);
                let result = if target.is_dir() {
                    std::fs::remove_dir_all(&target)
                } else {
                    std::fs::remove_file(&target)
                };
                match result {
                    Ok(()) => {
                        channel
                            .send(&ChannelMsg::SftpOk {
                                message: format!("removed {}", target.display()),
                            })
                            .await?;
                    }
                    Err(e) => {
                        channel
                            .send(&ChannelMsg::SftpError {
                                message: e.to_string(),
                            })
                            .await?;
                    }
                }
            }

            ChannelMsg::SftpRename { old_path, new_path } => {
                let old = resolve_path(&cwd, &home, &old_path);
                let new = resolve_path(&cwd, &home, &new_path);
                match std::fs::rename(&old, &new) {
                    Ok(()) => {
                        channel
                            .send(&ChannelMsg::SftpOk {
                                message: format!(
                                    "{} -> {}",
                                    old.display(),
                                    new.display()
                                ),
                            })
                            .await?;
                    }
                    Err(e) => {
                        channel
                            .send(&ChannelMsg::SftpError {
                                message: e.to_string(),
                            })
                            .await?;
                    }
                }
            }

            ChannelMsg::SftpRealpath { path } => {
                let target = resolve_path(&cwd, &home, &path);
                // Validate the path exists and is a directory (for cd)
                match std::fs::metadata(&target) {
                    Ok(meta) if meta.is_dir() => {
                        cwd = target.clone();
                        channel
                            .send(&ChannelMsg::SftpOk {
                                message: target.to_string_lossy().to_string(),
                            })
                            .await?;
                    }
                    Ok(_) => {
                        channel
                            .send(&ChannelMsg::SftpError {
                                message: format!("{}: not a directory", target.display()),
                            })
                            .await?;
                    }
                    Err(e) => {
                        channel
                            .send(&ChannelMsg::SftpError {
                                message: e.to_string(),
                            })
                            .await?;
                    }
                }
            }

            ChannelMsg::Eof | ChannelMsg::Close => break,

            other => {
                tracing::debug!("sftp: ignoring message: {other:?}");
            }
        }
    }

    tracing::info!(user = %username, "sftp session ended");
    Ok(())
}

fn resolve_path(cwd: &Path, home: &str, path: &str) -> PathBuf {
    if path.len() > MAX_PATH_LEN {
        return cwd.to_path_buf();
    }

    if path == "~" || path == "~/" {
        PathBuf::from(home)
    } else if let Some(rest) = path.strip_prefix("~/") {
        PathBuf::from(home).join(rest)
    } else if path.starts_with('/') {
        PathBuf::from(path)
    } else if path == "." || path.is_empty() {
        cwd.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn list_dir(path: &Path) -> Result<Vec<ManifestEntry>, std::io::Error> {
    let mut entries = Vec::new();

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = std::fs::metadata(entry.path())?;
        let name = entry.file_name().to_string_lossy().to_string();

        entries.push(ManifestEntry {
            path: name,
            size: meta.len(),
            mode: meta.mode(),
            is_dir: meta.is_dir(),
            mtime: meta.mtime() as u64,
            atime: meta.atime() as u64,
        });
    }

    // Sort: directories first, then alphabetical
    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then(a.path.cmp(&b.path))
    });

    Ok(entries)
}

fn stat_path(path: &Path) -> Result<ChannelMsg, std::io::Error> {
    let meta = std::fs::metadata(path)?;
    Ok(ChannelMsg::SftpStatResult {
        path: path.to_string_lossy().to_string(),
        size: meta.len(),
        mode: meta.mode(),
        mtime: meta.mtime() as u64,
        atime: meta.atime() as u64,
        is_dir: meta.is_dir(),
    })
}
