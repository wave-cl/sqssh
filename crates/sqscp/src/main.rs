use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use sqssh_core::client;
use sqssh_core::protocol::{
    self, ChannelType, RawChunkHeader, RawFileHeader, RAW_CHUNK_SIZE,
    RAW_DOWNLOAD_CHUNK, RAW_DOWNLOAD_DATA, RAW_MANIFEST_RESPONSE, RAW_TRANSFER_RESULT,
};
use sqssh_core::stream::Channel;
use tokio::sync::Semaphore;

#[derive(Parser)]
#[command(name = "sqscp", about = "sqssh secure file copy")]
struct Cli {
    /// Source(s) and destination
    #[arg(required = true, num_args = 2..)]
    args: Vec<String>,

    /// Port (UDP)
    #[arg(short = 'P', long)]
    port: Option<u16>,

    /// Identity file (private key)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Recursive copy
    #[arg(short = 'r', long)]
    recursive: bool,

    /// Preserve modification times
    #[arg(short = 'p', long = "preserve")]
    preserve: bool,

    /// Max concurrent transfers
    #[arg(short = 'j', long, default_value = "8")]
    jobs: usize,

    /// Bandwidth limit in KB/s (0 = unlimited)
    #[arg(short = 'l', long, default_value = "0")]
    limit: u64,

    /// Quiet mode (no progress output)
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Verbose mode
    #[arg(short = 'v', long)]
    verbose: bool,
}

/// Shared progress state.
struct Progress {
    total_files: usize,
    completed: AtomicUsize,
    total_bytes: AtomicU64,
    transferred_bytes: AtomicU64,
    start: Instant,
    quiet: bool,
}

impl Progress {
    fn new(total_files: usize, quiet: bool) -> Self {
        Self {
            total_files,
            completed: AtomicUsize::new(0),
            total_bytes: AtomicU64::new(0),
            transferred_bytes: AtomicU64::new(0),
            start: Instant::now(),
            quiet,
        }
    }

    fn set_total_bytes(&self, bytes: u64) {
        self.total_bytes.store(bytes, Ordering::Relaxed);
    }

    fn add_transferred(&self, bytes: u64) {
        self.transferred_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn file_done(&self, name: &str) {
        let done = self.completed.fetch_add(1, Ordering::Relaxed) + 1;
        if !self.quiet {
            let elapsed = self.start.elapsed().as_secs_f64();
            let transferred = self.transferred_bytes.load(Ordering::Relaxed);
            let speed = if elapsed > 0.0 {
                transferred as f64 / elapsed
            } else {
                0.0
            };
            eprintln!(
                "{name}  ({done}/{total})  {speed}/s",
                total = self.total_files,
                speed = format_bytes(speed as u64),
            );
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1}GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt::init();
    }

    if let Err(e) = run(cli).await {
        eprintln!("sqscp: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sources = &cli.args[..cli.args.len() - 1];
    let destination = &cli.args[cli.args.len() - 1];

    if let Some(remote) = client::parse_remote(destination) {
        upload(sources, &remote, &cli).await
    } else if sources.len() == 1 {
        if let Some(remote) = client::parse_remote(&sources[0]) {
            download(&remote, destination, &cli).await
        } else {
            Err("either source or destination must be remote (user@host:path)".into())
        }
    } else {
        Err("for multiple sources, destination must be remote".into())
    }
}

// -- Upload (raw uni streams) --

async fn upload(
    sources: &[String],
    remote: &client::RemoteSpec,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = client::connect(
        &remote.host,
        Some(&remote.user),
        cli.port,
        cli.identity.as_deref(),
    )
    .await?;

    let remote_path = remote.path.as_deref().unwrap_or(".");

    // Build file list: (local_path, remote_relative_path)
    let mut files: Vec<(PathBuf, String)> = Vec::new();

    for source in sources {
        let path = PathBuf::from(source);
        if path.is_dir()
            || (path.is_symlink()
                && std::fs::metadata(&path)
                    .map(|m| m.is_dir())
                    .unwrap_or(false))
        {
            if !cli.recursive {
                eprintln!("sqscp: {source}: is a directory (use -r)");
                continue;
            }
            let dir_name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| source.clone());
            walk_local_dir(&path, &path, &dir_name, &mut files)?;
        } else if path.exists() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| source.clone());
            files.push((path, name));
        } else {
            eprintln!("sqscp: {source}: no such file or directory");
        }
    }

    if files.is_empty() {
        return Err("no files to transfer".into());
    }

    let files_total = files.len();
    let total_bytes: u64 = files
        .iter()
        .filter_map(|(p, _)| std::fs::metadata(p).ok().map(|m| m.len()))
        .sum();
    let progress = Arc::new(Progress::new(files.len(), cli.quiet));
    progress.set_total_bytes(total_bytes);

    let sem = Arc::new(Semaphore::new(cli.jobs));
    let conn = Arc::new(conn.conn);
    let remote_path = remote_path.to_string();
    let preserve = cli.preserve;
    let bw_limit = cli.limit;
    let jobs = cli.jobs;
    let mut handles = Vec::new();

    // Single file with j > 1: use chunked parallel upload
    let is_dir_dest = remote_path.ends_with('/') || remote_path == "~" || remote_path == ".";
    if files_total == 1 && jobs > 1 {
        let (local_path, rel_name) = files.into_iter().next().unwrap();
        let upload_path = if is_dir_dest {
            format!("{}/{}", remote_path.trim_end_matches('/'), rel_name)
        } else {
            remote_path.clone()
        };

        upload_file_chunked(&conn, &local_path, &upload_path, &rel_name, preserve, bw_limit, jobs, &progress).await?;
        progress.file_done(&rel_name);
    } else {
        for (local_path, rel_name) in files.into_iter() {
            let sem = sem.clone();
            let conn = conn.clone();
            let dest = remote_path.clone();
            let progress = progress.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                let is_dir = files_total > 1 || dest.ends_with('/') || dest == "~" || dest == ".";
                let upload_path = if is_dir {
                    format!("{}/{}", dest.trim_end_matches('/'), rel_name)
                } else {
                    dest.clone()
                };

                upload_file_raw(&conn, &local_path, &upload_path, &rel_name, preserve, bw_limit, &progress).await?;
                progress.file_done(&rel_name);

                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            });

            handles.push(handle);
        }
    }

    let mut errors = 0;
    for handle in handles {
        if let Err(e) = handle.await? {
            eprintln!("sqscp: {e}");
            errors += 1;
        }
    }

    if !cli.quiet {
        let elapsed = progress.start.elapsed().as_secs_f64();
        let transferred = progress.transferred_bytes.load(Ordering::Relaxed);
        eprintln!(
            "{} transferred in {:.1}s ({}/s)",
            format_bytes(transferred),
            elapsed,
            format_bytes((transferred as f64 / elapsed) as u64),
        );
    }

    // Connection drops naturally when Arc is released.
    // Stream data is flushed by stopped() in upload_file_raw/upload_file_chunked.

    if errors > 0 {
        Err(format!("{errors} file(s) failed").into())
    } else {
        Ok(())
    }
}

/// Upload a single file via a raw unidirectional QUIC stream.
async fn upload_file_raw(
    conn: &quinn::Connection,
    local_path: &Path,
    remote_path: &str,
    _display_name: &str,
    preserve: bool,
    bw_limit_kbps: u64,
    progress: &Progress,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Read;

    let meta = std::fs::metadata(local_path)?;
    let size = meta.len();
    let mode = meta.mode();
    let (mtime, atime) = if preserve {
        (meta.mtime() as u64, meta.atime() as u64)
    } else {
        (0, 0)
    };

    // Open unidirectional stream
    let mut send: quinn::SendStream = conn.open_uni().await
        .map_err(|e| format!("failed to open upload stream: {e}"))?;

    // Write binary header
    let header = RawFileHeader {
        path: remote_path.to_string(),
        size,
        mode,
        mtime,
        atime,
    };
    send.write_all(&header.encode_upload()).await
        .map_err(|e| format!("failed to write header: {e}"))?;

    // Stream raw file data
    let mut file = std::fs::File::open(local_path)?;
    let mut buf = vec![0u8; RAW_CHUNK_SIZE];
    let bytes_per_tick = if bw_limit_kbps > 0 {
        bw_limit_kbps * 1024 / 10
    } else {
        0
    };
    let mut sent_this_tick: u64 = 0;
    let mut tick_start = Instant::now();

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        send.write_all(&buf[..n]).await
            .map_err(|e| format!("write error: {e}"))?;

        progress.add_transferred(n as u64);

        if bytes_per_tick > 0 {
            sent_this_tick += n as u64;
            if sent_this_tick >= bytes_per_tick {
                let elapsed = tick_start.elapsed();
                if elapsed < std::time::Duration::from_millis(100) {
                    tokio::time::sleep(std::time::Duration::from_millis(100) - elapsed).await;
                }
                sent_this_tick = 0;
                tick_start = Instant::now();
            }
        }
    }

    // FIN = EOF, then wait for peer to process all data
    send.finish()
        .map_err(|e| format!("finish error: {e}"))?;
    // stopped() resolves when the peer has read all data (stream fully drained)
    // or when they send STOP_SENDING
    // Don't wait for stopped() — finish() sends FIN, peer acks naturally.

    Ok(())
}

/// Upload a single file using multiple parallel uni streams (chunked).
async fn upload_file_chunked(
    conn: &quinn::Connection,
    local_path: &Path,
    remote_path: &str,
    _display_name: &str,
    preserve: bool,
    bw_limit_kbps: u64,
    jobs: usize,
    progress: &Arc<Progress>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::FileExt;

    let meta = std::fs::metadata(local_path)?;
    let file_size = meta.len();
    let mode = meta.mode();
    let (mtime, atime) = if preserve {
        (meta.mtime() as u64, meta.atime() as u64)
    } else {
        (0, 0)
    };

    let chunk_size = file_size / jobs as u64;
    let file = Arc::new(std::fs::File::open(local_path)?);
    let mut handles = Vec::new();

    for i in 0..jobs {
        let conn = conn.clone();
        let file = file.clone();
        let path = remote_path.to_string();
        let progress = progress.clone();

        let offset = i as u64 * chunk_size;
        let length = if i == jobs - 1 {
            file_size - offset // last chunk gets remainder
        } else {
            chunk_size
        };

        let handle = tokio::spawn(async move {
            let mut send: quinn::SendStream = conn.open_uni().await
                .map_err(|e| format!("failed to open chunk stream: {e}"))?;

            let header = RawChunkHeader {
                path,
                file_size,
                mode,
                mtime,
                atime,
                offset,
                chunk_length: length,
            };
            send.write_all(&header.encode_upload()).await
                .map_err(|e| format!("chunk header write: {e}"))?;

            // Read from file at offset using pread
            let mut buf = vec![0u8; RAW_CHUNK_SIZE];
            let mut sent: u64 = 0;
            let bytes_per_tick = if bw_limit_kbps > 0 {
                bw_limit_kbps * 1024 / 10 / jobs as u64
            } else {
                0
            };
            let mut sent_this_tick: u64 = 0;
            let mut tick_start = Instant::now();

            while sent < length {
                let to_read = std::cmp::min(RAW_CHUNK_SIZE as u64, length - sent) as usize;
                let n = file.read_at(&mut buf[..to_read], offset + sent)
                    .map_err(|e| format!("read_at error: {e}"))?;
                if n == 0 { break; }

                send.write_all(&buf[..n]).await
                    .map_err(|e| format!("chunk write: {e}"))?;
                sent += n as u64;
                progress.add_transferred(n as u64);

                if bytes_per_tick > 0 {
                    sent_this_tick += n as u64;
                    if sent_this_tick >= bytes_per_tick {
                        let elapsed = tick_start.elapsed();
                        if elapsed < std::time::Duration::from_millis(100) {
                            tokio::time::sleep(std::time::Duration::from_millis(100) - elapsed).await;
                        }
                        sent_this_tick = 0;
                        tick_start = Instant::now();
                    }
                }
            }

            send.finish().map_err(|e| format!("finish: {e}"))?;
            // Don't wait for stopped() — finish() sends FIN, peer acks naturally.
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.await??;
    }

    Ok(())
}

// -- Download (metadata bidi + raw uni streams) --

async fn download(
    remote: &client::RemoteSpec,
    local_dest: &str,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn = client::connect(
        &remote.host,
        Some(&remote.user),
        cli.port,
        cli.identity.as_deref(),
    )
    .await?;

    let remote_path = remote.path.as_deref().unwrap_or(".");
    let conn = Arc::new(conn.conn);

    // Open bidi channel with RawDownload request
    let mut channel = Channel::open(
        &conn,
        ChannelType::RawDownload {
            path: remote_path.to_string(),
            jobs: cli.jobs as u32,
        },
    )
    .await?;

    // Wait for confirm
    match channel.recv().await? {
        sqssh_core::protocol::ChannelMsg::ChannelOpenConfirm => {}
        sqssh_core::protocol::ChannelMsg::ChannelOpenFailure { description, .. } => {
            return Err(format!("channel open failed: {description}").into());
        }
        other => {
            return Err(format!("unexpected: {other:?}").into());
        }
    }

    // Read response type from raw bytes on the channel's recv stream
    let mut type_buf = [0u8; 1];
    channel.recv_stream().read_exact(&mut type_buf).await
        .map_err(|e| format!("failed to read response type: {e}"))?;

    match type_buf[0] {
        RAW_MANIFEST_RESPONSE => {
            // Directory download
            if !cli.recursive {
                return Err("remote path is a directory (use -r)".into());
            }

            let entries = protocol::decode_manifest_response(channel.recv_stream()).await?;

            let source_dir_name = Path::new(remote_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let dest = if source_dir_name.is_empty() {
                PathBuf::from(local_dest)
            } else {
                PathBuf::from(local_dest).join(&source_dir_name)
            };
            std::fs::create_dir_all(&dest)?;

            // Create directories first
            for entry in &entries {
                if entry.is_dir {
                    std::fs::create_dir_all(dest.join(&entry.path))?;
                }
            }

            let file_entries: Vec<_> = entries.iter().filter(|e| !e.is_dir).cloned().collect();
            let total_bytes: u64 = file_entries.iter().map(|e| e.size).sum();
            let progress = Arc::new(Progress::new(file_entries.len(), cli.quiet));
            progress.set_total_bytes(total_bytes);

            // Server will send uni streams for each file
            let sem = Arc::new(Semaphore::new(cli.jobs));
            let mut handles = Vec::new();

            for entry in file_entries.into_iter() {
                let sem = sem.clone();
                let conn = conn.clone();
                let dest = dest.clone();
                let progress = progress.clone();
                let preserve = cli.preserve;
                let bw_limit = cli.limit;

                let handle = tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();

                    // Accept uni stream from server
                    let mut recv = conn.accept_uni().await
                        .map_err(|e| format!("failed to accept download stream: {e}"))?;

                    // Read type byte
                    let mut tb = [0u8; 1];
                    recv.read_exact(&mut tb).await
                        .map_err(|e| format!("failed to read stream type: {e}"))?;

                    if tb[0] != RAW_DOWNLOAD_DATA {
                        return Err(format!("unexpected stream type: {:#x}", tb[0]).into());
                    }

                    let header = RawFileHeader::decode(&mut recv).await?;
                    let local_path = dest.join(&header.path);
                    if let Some(parent) = local_path.parent() {
                        std::fs::create_dir_all(parent).ok();
                    }

                    download_file_raw(&mut recv, &local_path, &header, preserve, bw_limit, &progress).await?;
                    progress.file_done(&entry.path);

                    Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                });

                handles.push(handle);
            }

            let mut errors = 0;
            for handle in handles {
                if let Err(e) = handle.await? {
                    eprintln!("sqscp: {e}");
                    errors += 1;
                }
            }

            if !cli.quiet {
                let elapsed = progress.start.elapsed().as_secs_f64();
                let transferred = progress.transferred_bytes.load(Ordering::Relaxed);
                eprintln!(
                    "{} transferred in {:.1}s ({}/s)",
                    format_bytes(transferred),
                    elapsed,
                    format_bytes((transferred as f64 / elapsed) as u64),
                );
            }

            if errors > 0 {
                return Err(format!("{errors} file(s) failed").into());
            }
        }
        RAW_DOWNLOAD_DATA => {
            // Single file, single stream
            let mut recv = conn.accept_uni().await
                .map_err(|e| format!("failed to accept download stream: {e}"))?;

            let mut tb = [0u8; 1];
            recv.read_exact(&mut tb).await
                .map_err(|e| format!("failed to read stream type: {e}"))?;

            let header = RawFileHeader::decode(&mut recv).await?;

            let dest = if Path::new(local_dest).is_dir() {
                PathBuf::from(local_dest).join(&header.path)
            } else {
                PathBuf::from(local_dest)
            };

            let progress = Progress::new(1, cli.quiet);
            progress.set_total_bytes(header.size);
            download_file_raw(&mut recv, &dest, &header, cli.preserve, cli.limit, &progress).await?;
            progress.file_done(&header.path);

            if !cli.quiet {
                let elapsed = progress.start.elapsed().as_secs_f64();
                eprintln!(
                    "{} transferred in {:.1}s ({}/s)",
                    format_bytes(header.size),
                    elapsed,
                    format_bytes((header.size as f64 / elapsed) as u64),
                );
            }
        }
        RAW_DOWNLOAD_CHUNK => {
            // Single file, chunked across multiple uni streams
            // Read the first chunk header from the bidi to get file metadata
            let first_header = RawChunkHeader::decode(channel.recv_stream()).await?;

            let dest = if Path::new(local_dest).is_dir() {
                PathBuf::from(local_dest).join(&first_header.path)
            } else {
                PathBuf::from(local_dest)
            };

            // Pre-create file at full size
            let file = std::fs::File::create(&dest)?;
            file.set_len(first_header.file_size)?;
            let file = Arc::new(file);

            let progress = Arc::new(Progress::new(1, cli.quiet));
            progress.set_total_bytes(first_header.file_size);

            // Accept the first chunk's uni stream + remaining chunks
            let jobs = cli.jobs;
            let mut handles = Vec::new();

            for _ in 0..jobs {
                let conn = conn.clone();
                let file = file.clone();
                let progress = progress.clone();
                let preserve = cli.preserve;

                let handle = tokio::spawn(async move {
                    let mut recv = conn.accept_uni().await
                        .map_err(|e| format!("failed to accept chunk stream: {e}"))?;

                    let mut tb = [0u8; 1];
                    recv.read_exact(&mut tb).await
                        .map_err(|e| format!("chunk type: {e}"))?;

                    let chunk = RawChunkHeader::decode(&mut recv).await?;

                    // Write at offset using pwrite
                    download_chunk_raw(&mut recv, &file, &chunk, &progress).await?;

                    Ok::<(u32, u64, u64, bool), Box<dyn std::error::Error + Send + Sync>>(
                        (chunk.mode, chunk.mtime, chunk.atime, preserve)
                    )
                });

                handles.push(handle);
            }

            let mut mode = 0u32;
            let mut mtime = 0u64;
            let mut atime = 0u64;
            let mut do_preserve = false;

            for handle in handles {
                let (m, mt, at, p) = handle.await??;
                mode = m;
                mtime = mt;
                atime = at;
                do_preserve = p;
            }

            // Finalize file metadata
            drop(file);
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(mode))?;
            if do_preserve && mtime > 0 {
                set_file_times(&dest, atime, mtime)?;
            }

            progress.file_done(&first_header.path);

            if !cli.quiet {
                let elapsed = progress.start.elapsed().as_secs_f64();
                eprintln!(
                    "{} transferred in {:.1}s ({}/s)",
                    format_bytes(first_header.file_size),
                    elapsed,
                    format_bytes((first_header.file_size as f64 / elapsed) as u64),
                );
            }
        }
        RAW_TRANSFER_RESULT => {
            let (success, message) = protocol::decode_transfer_result(channel.recv_stream()).await?;
            if !success {
                return Err(format!("remote error: {message}").into());
            }
        }
        other => {
            return Err(format!("unexpected response type: {other:#x}").into());
        }
    }

    Ok(())
}

/// Download file data from a raw uni stream directly to disk.
async fn download_file_raw(
    recv: &mut quinn::RecvStream,
    path: &Path,
    header: &RawFileHeader,
    preserve: bool,
    bw_limit_kbps: u64,
    progress: &Progress,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let mut file = std::fs::File::create(path)?;
    let mut written: u64 = 0;
    let mut buf = vec![0u8; RAW_CHUNK_SIZE];
    let bytes_per_tick = if bw_limit_kbps > 0 {
        bw_limit_kbps * 1024 / 10
    } else {
        0
    };
    let mut received_this_tick: u64 = 0;
    let mut tick_start = Instant::now();

    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                file.write_all(&buf[..n])?;
                written += n as u64;
                progress.add_transferred(n as u64);

                if bytes_per_tick > 0 {
                    received_this_tick += n as u64;
                    if received_this_tick >= bytes_per_tick {
                        let elapsed = tick_start.elapsed();
                        if elapsed < std::time::Duration::from_millis(100) {
                            tokio::time::sleep(std::time::Duration::from_millis(100) - elapsed)
                                .await;
                        }
                        received_this_tick = 0;
                        tick_start = Instant::now();
                    }
                }
            }
            Ok(None) => break, // FIN received = EOF
            Err(e) => return Err(format!("read error: {e}").into()),
        }
    }

    file.flush()?;
    drop(file);

    if written != header.size {
        eprintln!(
            "sqscp: warning: size mismatch for {}: expected {}, got {written}",
            path.display(),
            header.size,
        );
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(header.mode))?;

    if preserve && header.mtime > 0 {
        set_file_times(path, header.atime, header.mtime)?;
    }

    Ok(())
}

/// Download a chunk from a raw uni stream directly to a file at the given offset.
async fn download_chunk_raw(
    recv: &mut quinn::RecvStream,
    file: &std::fs::File,
    chunk: &RawChunkHeader,
    progress: &Progress,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::fs::FileExt;

    let mut buf = vec![0u8; RAW_CHUNK_SIZE];
    let mut written: u64 = 0;

    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                file.write_at(&buf[..n], chunk.offset + written)
                    .map_err(|e| format!("write_at error: {e}"))?;
                written += n as u64;
                progress.add_transferred(n as u64);
            }
            Ok(None) => break,
            Err(e) => return Err(format!("chunk read error: {e}").into()),
        }
    }

    if written != chunk.chunk_length {
        eprintln!(
            "sqscp: warning: chunk size mismatch: expected {}, got {written}",
            chunk.chunk_length,
        );
    }

    Ok(())
}

fn set_file_times(
    path: &Path,
    atime: u64,
    mtime: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let times = [
        libc::timespec {
            tv_sec: atime as i64,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: mtime as i64,
            tv_nsec: 0,
        },
    ];
    let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())?;
    let ret = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    if ret != 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

// -- Helpers --

fn walk_local_dir(
    root: &Path,
    base: &Path,
    prefix: &str,
    files: &mut Vec<(PathBuf, String)>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let meta = std::fs::metadata(entry.path())?;
        let relative = entry
            .path()
            .strip_prefix(base)
            .unwrap_or(&entry.path())
            .to_string_lossy()
            .to_string();
        let prefixed = format!("{prefix}/{relative}");

        if meta.is_dir() {
            walk_local_dir(&entry.path(), base, prefix, files)?;
        } else if meta.is_file() {
            files.push((entry.path(), prefixed));
        }
    }
    Ok(())
}
