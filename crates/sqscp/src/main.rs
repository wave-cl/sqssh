use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use clap::Parser;
use sqssh_core::client;
use sqssh_core::protocol::{ChannelMsg, ChannelType, TransferDirection};
use sqssh_core::stream::Channel;
use tokio::sync::Semaphore;

/// Chunk size for reading files (64 KB).
const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Parser)]
#[command(name = "sqscp", about = "sqssh secure file copy")]
struct Cli {
    /// Source(s) and destination
    #[arg(required = true, num_args = 2..)]
    args: Vec<String>,

    /// Port (UDP)
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Identity file (private key)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,

    /// Recursive copy
    #[arg(short = 'r', long)]
    recursive: bool,

    /// Preserve modification times
    #[arg(short = 'P', long = "preserve")]
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

// -- Upload --

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
        if path.is_dir() || (path.is_symlink() && std::fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(false)) {
            if !cli.recursive {
                eprintln!("sqscp: {source}: is a directory (use -r)");
                continue;
            }
            // Like scp: create source dir name at destination
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
    let mut handles = Vec::new();

    for (local_path, rel_name) in files.into_iter() {
        let sem = sem.clone();
        let conn = conn.clone();
        let dest = remote_path.clone();
        let progress = progress.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let upload_path = if files_total > 1 || dest.ends_with('/') {
                format!("{}/{}", dest.trim_end_matches('/'), rel_name)
            } else {
                dest.clone()
            };

            let mut channel = Channel::open(
                &conn,
                ChannelType::FileTransfer {
                    direction: TransferDirection::Upload,
                    path: upload_path,
                },
            )
            .await?;

            match channel.recv().await? {
                ChannelMsg::ChannelOpenConfirm => {}
                ChannelMsg::ChannelOpenFailure { description, .. } => {
                    return Err(format!("channel open failed: {description}").into());
                }
                other => {
                    return Err(format!("unexpected: {other:?}").into());
                }
            }

            upload_file(&mut channel, &local_path, &rel_name, preserve, bw_limit, &progress).await?;
            progress.file_done(&rel_name);

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
        Err(format!("{errors} file(s) failed").into())
    } else {
        Ok(())
    }
}

async fn upload_file(
    channel: &mut Channel,
    local_path: &Path,
    name: &str,
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

    channel
        .send(&ChannelMsg::FileHeader {
            path: name.to_string(),
            size,
            mode,
            mtime,
            atime,
        })
        .await?;

    let mut file = std::fs::File::open(local_path)?;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let bytes_per_tick = if bw_limit_kbps > 0 {
        bw_limit_kbps * 1024 / 10 // allow this many bytes per 100ms
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
        channel
            .send(&ChannelMsg::Data {
                payload: buf[..n].to_vec(),
            })
            .await?;

        progress.add_transferred(n as u64);

        // Bandwidth limiting
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

    channel.send(&ChannelMsg::Eof).await?;

    match channel.recv().await? {
        ChannelMsg::FileResult { success, message } => {
            if !success {
                return Err(format!("upload failed for {name}: {message}").into());
            }
        }
        other => {
            return Err(format!("unexpected response: {other:?}").into());
        }
    }

    Ok(())
}

// -- Download --

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

    let mut channel = Channel::open(
        &conn,
        ChannelType::FileTransfer {
            direction: TransferDirection::Download,
            path: remote_path.to_string(),
        },
    )
    .await?;

    match channel.recv().await? {
        ChannelMsg::ChannelOpenConfirm => {}
        ChannelMsg::ChannelOpenFailure { description, .. } => {
            return Err(format!("channel open failed: {description}").into());
        }
        other => {
            return Err(format!("unexpected: {other:?}").into());
        }
    }

    match channel.recv().await? {
        ChannelMsg::FileResult {
            success: false,
            message,
        } => {
            return Err(format!("remote error: {message}").into());
        }
        ChannelMsg::FileHeader {
            path,
            size,
            mode,
            mtime,
            atime,
        } => {
            let dest = if Path::new(local_dest).is_dir() {
                PathBuf::from(local_dest).join(&path)
            } else {
                PathBuf::from(local_dest)
            };

            let progress = Progress::new(1, cli.quiet);
            progress.set_total_bytes(size);
            download_file_data(&mut channel, &dest, size, mode, mtime, atime, cli.preserve, cli.limit, &progress).await?;
            progress.file_done(&path);

            if !cli.quiet {
                let elapsed = progress.start.elapsed().as_secs_f64();
                eprintln!(
                    "{} transferred in {:.1}s ({}/s)",
                    format_bytes(size),
                    elapsed,
                    format_bytes((size as f64 / elapsed) as u64),
                );
            }
        }
        ChannelMsg::FileManifest { entries } => {
            if !cli.recursive {
                return Err("remote path is a directory (use -r)".into());
            }

            // Like scp: create source dir name inside destination
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

            let file_entries: Vec<_> = entries.iter().filter(|e| !e.is_dir).cloned().collect();
            let total_bytes: u64 = file_entries.iter().map(|e| e.size).sum();
            let progress = Arc::new(Progress::new(file_entries.len(), cli.quiet));
            progress.set_total_bytes(total_bytes);

            // Create directories first
            for entry in &entries {
                if entry.is_dir {
                    std::fs::create_dir_all(dest.join(&entry.path))?;
                }
            }

            let sem = Arc::new(Semaphore::new(cli.jobs));
            let remote_path_owned = remote_path.to_string();
            let preserve = cli.preserve;
            let bw_limit = cli.limit;
            let mut handles = Vec::new();

            for entry in file_entries.into_iter() {
                let sem = sem.clone();
                let conn = conn.clone();
                let dest = dest.clone();
                let base = remote_path_owned.clone();
                let progress = progress.clone();

                let handle = tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();

                    let download_path =
                        format!("{}/{}", base.trim_end_matches('/'), entry.path);
                    let mut ch = Channel::open(
                        &conn,
                        ChannelType::FileTransfer {
                            direction: TransferDirection::Download,
                            path: download_path,
                        },
                    )
                    .await?;

                    match ch.recv().await? {
                        ChannelMsg::ChannelOpenConfirm => {}
                        ChannelMsg::ChannelOpenFailure { description, .. } => {
                            return Err(format!("channel open failed: {description}").into());
                        }
                        _ => {}
                    }

                    match ch.recv().await? {
                        ChannelMsg::FileHeader {
                            size, mode, mtime, atime, ..
                        } => {
                            let local_path = dest.join(&entry.path);
                            if let Some(parent) = local_path.parent() {
                                std::fs::create_dir_all(parent).ok();
                            }
                            download_file_data(&mut ch, &local_path, size, mode, mtime, atime, preserve, bw_limit, &progress)
                                .await?;
                            progress.file_done(&entry.path);
                        }
                        ChannelMsg::FileResult {
                            success: false,
                            message,
                        } => {
                            return Err(
                                format!("remote error for {}: {message}", entry.path).into()
                            );
                        }
                        other => {
                            return Err(format!("expected FileHeader, got {other:?}").into());
                        }
                    }

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
        other => {
            return Err(format!("unexpected: {other:?}").into());
        }
    }

    Ok(())
}

async fn download_file_data(
    channel: &mut Channel,
    path: &Path,
    expected_size: u64,
    mode: u32,
    mtime: u64,
    atime: u64,
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
    let bytes_per_tick = if bw_limit_kbps > 0 {
        bw_limit_kbps * 1024 / 10
    } else {
        0
    };
    let mut received_this_tick: u64 = 0;
    let mut tick_start = Instant::now();

    loop {
        match channel.recv().await? {
            ChannelMsg::Data { payload } => {
                let n = payload.len() as u64;
                file.write_all(&payload)?;
                written += n;
                progress.add_transferred(n);

                // Bandwidth limiting
                if bytes_per_tick > 0 {
                    received_this_tick += n;
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
            ChannelMsg::Eof => break,
            other => {
                return Err(format!("unexpected during download: {other:?}").into());
            }
        }
    }

    file.flush()?;
    drop(file);

    if written != expected_size {
        eprintln!(
            "sqscp: warning: size mismatch for {}: expected {expected_size}, got {written}",
            path.display()
        );
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;

    // Preserve timestamps if requested
    if preserve && mtime > 0 {
        set_file_times(path, atime, mtime)?;
    }

    channel
        .send(&ChannelMsg::FileResult {
            success: true,
            message: String::new(),
        })
        .await?;

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
        // Follow symlinks for metadata
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
        // Symlinks are followed by std::fs::metadata (not symlink_metadata)
    }
    Ok(())
}
