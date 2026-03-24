use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sqssh_core::protocol::{ManifestEntry, RawFileHeader, SftpCmd, SftpResp, RAW_CHUNK_SIZE};
use tokio::io::AsyncWriteExt;

/// Maximum path length.
const MAX_PATH_LEN: usize = 4096;

/// Handle an interactive SFTP session over raw QUIC streams.
pub async fn handle_sftp(
    sftp_send: &mut quinn::SendStream,
    sftp_recv: &mut quinn::RecvStream,
    conn: &quinn::Connection,
    username: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_uid, _gid, home, _shell) = super::pty_handler::lookup_user(username)?;
    let mut cwd = PathBuf::from(&home);

    tracing::info!(user = %username, "sftp session started");

    loop {
        let cmd = match SftpCmd::decode(sftp_recv).await {
            Ok(c) => c,
            Err(_) => break,
        };

        match cmd {
            SftpCmd::ListDir { path } => {
                let target = resolve_path(&cwd, &home, &path);
                match list_dir(&target) {
                    Ok(entries) => {
                        sftp_send.write_all(&SftpResp::DirListing { entries }.encode()).await?;
                    }
                    Err(e) => {
                        sftp_send.write_all(&SftpResp::Error { message: e.to_string() }.encode()).await?;
                    }
                }
            }

            SftpCmd::Stat { path } => {
                let target = resolve_path(&cwd, &home, &path);
                match stat_path(&target) {
                    Ok(resp) => {
                        sftp_send.write_all(&resp.encode()).await?;
                    }
                    Err(e) => {
                        sftp_send.write_all(&SftpResp::Error { message: e.to_string() }.encode()).await?;
                    }
                }
            }

            SftpCmd::Mkdir { path, mode } => {
                let target = resolve_path(&cwd, &home, &path);
                match std::fs::create_dir(&target) {
                    Ok(()) => {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).ok();
                        sftp_send.write_all(&SftpResp::Ok {
                            message: format!("created {}", target.display()),
                        }.encode()).await?;
                    }
                    Err(e) => {
                        sftp_send.write_all(&SftpResp::Error { message: e.to_string() }.encode()).await?;
                    }
                }
            }

            SftpCmd::Remove { path } => {
                let target = resolve_path(&cwd, &home, &path);
                let result = if target.is_dir() {
                    std::fs::remove_dir_all(&target)
                } else {
                    std::fs::remove_file(&target)
                };
                match result {
                    Ok(()) => {
                        sftp_send.write_all(&SftpResp::Ok {
                            message: format!("removed {}", target.display()),
                        }.encode()).await?;
                    }
                    Err(e) => {
                        sftp_send.write_all(&SftpResp::Error { message: e.to_string() }.encode()).await?;
                    }
                }
            }

            SftpCmd::Rename { old_path, new_path } => {
                let old = resolve_path(&cwd, &home, &old_path);
                let new = resolve_path(&cwd, &home, &new_path);
                match std::fs::rename(&old, &new) {
                    Ok(()) => {
                        sftp_send.write_all(&SftpResp::Ok {
                            message: format!("{} -> {}", old.display(), new.display()),
                        }.encode()).await?;
                    }
                    Err(e) => {
                        sftp_send.write_all(&SftpResp::Error { message: e.to_string() }.encode()).await?;
                    }
                }
            }

            SftpCmd::Realpath { path } => {
                let target = resolve_path(&cwd, &home, &path);
                match std::fs::metadata(&target) {
                    Ok(meta) if meta.is_dir() => {
                        cwd = target.clone();
                        sftp_send.write_all(&SftpResp::Ok {
                            message: target.to_string_lossy().to_string(),
                        }.encode()).await?;
                    }
                    Ok(_) => {
                        sftp_send.write_all(&SftpResp::Error {
                            message: format!("{}: not a directory", target.display()),
                        }.encode()).await?;
                    }
                    Err(e) => {
                        sftp_send.write_all(&SftpResp::Error { message: e.to_string() }.encode()).await?;
                    }
                }
            }

            SftpCmd::Get { path } => {
                let target = resolve_path(&cwd, &home, &path);
                match std::fs::metadata(&target) {
                    Ok(meta) if meta.is_file() => {
                        // Send file on uni stream
                        match conn.open_uni().await {
                            Ok(mut uni_send) => {
                                let header = RawFileHeader {
                                    path: target.to_string_lossy().to_string(),
                                    size: meta.len(),
                                    mode: meta.mode(),
                                    mtime: meta.mtime() as u64,
                                    atime: meta.atime() as u64,
                                };
                                uni_send.write_all(&header.encode_download()).await?;

                                let mut file = std::fs::File::open(&target)?;
                                let mut buf = vec![0u8; RAW_CHUNK_SIZE];
                                loop {
                                    let n = std::io::Read::read(&mut file, &mut buf)?;
                                    if n == 0 { break; }
                                    uni_send.write_all(&buf[..n]).await?;
                                }
                                uni_send.finish()?;
                            }
                            Err(e) => {
                                tracing::error!("sftp get: failed to open uni stream: {e}");
                            }
                        }
                    }
                    Ok(_) => {
                        // Can't send a directory — send empty uni stream? Or error on sftp.
                        // For now, just don't open the uni stream — client will timeout.
                        tracing::error!("sftp get: not a file: {}", target.display());
                    }
                    Err(e) => {
                        tracing::error!("sftp get: {e}");
                    }
                }
            }

            SftpCmd::Put => {
                // Client will send file on a uni stream — accept it
                match conn.accept_uni().await {
                    Ok(mut uni_recv) => {
                        let mut type_buf = [0u8; 1];
                        if let Err(e) = uni_recv.read_exact(&mut type_buf).await {
                            sftp_send.write_all(&SftpResp::Error {
                                message: format!("put: {e}"),
                            }.encode()).await?;
                            continue;
                        }

                        match RawFileHeader::decode(&mut uni_recv).await {
                            Ok(header) => {
                                let target = resolve_path(&cwd, &home, &header.path);
                                match super::file_handler::receive_raw_file(
                                    &mut uni_recv, &target, header.size, header.mode,
                                    header.mtime, header.atime,
                                ).await {
                                    Ok(()) => {
                                        sftp_send.write_all(&SftpResp::Ok {
                                            message: format!("{} bytes", header.size),
                                        }.encode()).await?;
                                    }
                                    Err(e) => {
                                        sftp_send.write_all(&SftpResp::Error {
                                            message: e.to_string(),
                                        }.encode()).await?;
                                    }
                                }
                            }
                            Err(e) => {
                                sftp_send.write_all(&SftpResp::Error {
                                    message: format!("put header: {e}"),
                                }.encode()).await?;
                            }
                        }
                    }
                    Err(e) => {
                        sftp_send.write_all(&SftpResp::Error {
                            message: format!("put: {e}"),
                        }.encode()).await?;
                    }
                }
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

    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir).then(a.path.cmp(&b.path))
    });

    Ok(entries)
}

fn stat_path(path: &Path) -> Result<SftpResp, std::io::Error> {
    let meta = std::fs::metadata(path)?;
    Ok(SftpResp::StatResult {
        path: path.to_string_lossy().to_string(),
        size: meta.len(),
        mode: meta.mode(),
        mtime: meta.mtime() as u64,
        atime: meta.atime() as u64,
        is_dir: meta.is_dir(),
    })
}
