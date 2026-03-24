use std::io::{self, BufRead, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use sqssh_core::client;
use sqssh_core::protocol::{ChannelMsg, ChannelType, ManifestEntry, TransferDirection};
use sqssh_core::stream::Channel;

const CHUNK_SIZE: usize = 64 * 1024;

#[derive(Parser)]
#[command(name = "sqsftp", about = "sqssh interactive file transfer")]
struct Cli {
    /// [user@]hostname
    destination: String,

    /// Port (UDP)
    #[arg(short = 'p', long)]
    port: Option<u16>,

    /// Identity file (private key)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli).await {
        eprintln!("sqsftp: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (user, host) = if let Some(at) = cli.destination.find('@') {
        (
            Some(cli.destination[..at].to_string()),
            cli.destination[at + 1..].to_string(),
        )
    } else {
        (None, cli.destination.clone())
    };

    let connection = client::connect(
        &host,
        user.as_deref(),
        cli.port,
        cli.identity.as_deref(),
    )
    .await?;

    let conn = Arc::new(connection.conn);

    // Open sftp command channel
    let mut sftp_channel = Channel::open(&conn, ChannelType::Sftp).await?;
    match sftp_channel.recv().await? {
        ChannelMsg::ChannelOpenConfirm => {}
        ChannelMsg::ChannelOpenFailure { description, .. } => {
            return Err(format!("sftp channel failed: {description}").into());
        }
        other => {
            return Err(format!("unexpected: {other:?}").into());
        }
    }

    // Get initial remote cwd
    sftp_channel
        .send(&ChannelMsg::SftpRealpath {
            path: ".".to_string(),
        })
        .await?;
    let mut remote_cwd = match sftp_channel.recv().await? {
        ChannelMsg::SftpOk { message } => message,
        _ => "~".to_string(),
    };

    let stdin = io::stdin();
    let mut reader = stdin.lock();

    loop {
        print!("sftp> ");
        io::stdout().flush()?;

        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break; // EOF
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, char::is_whitespace).collect();
        let cmd = parts[0];
        let arg1 = parts.get(1).copied().unwrap_or("");
        let arg2 = parts.get(2).copied().unwrap_or("");

        match cmd {
            "quit" | "exit" | "bye" => break,

            "help" | "?" => {
                println!("Commands:");
                println!("  ls [path]          List remote directory");
                println!("  cd path            Change remote directory");
                println!("  pwd                Print remote working directory");
                println!("  stat path          Show file/directory info");
                println!("  mkdir path         Create remote directory");
                println!("  rm path            Remove file or directory");
                println!("  rename old new     Rename/move file");
                println!("  get remote [local] Download file");
                println!("  put local [remote] Upload file");
                println!("  lcd path           Change local directory");
                println!("  lpwd               Print local working directory");
                println!("  lls [path]         List local directory");
                println!("  quit               Exit");
            }

            "pwd" => {
                println!("{remote_cwd}");
            }

            "lpwd" => {
                match std::env::current_dir() {
                    Ok(p) => println!("{}", p.display()),
                    Err(e) => eprintln!("lpwd: {e}"),
                }
            }

            "lcd" => {
                if arg1.is_empty() {
                    eprintln!("lcd: missing path");
                } else if let Err(e) = std::env::set_current_dir(arg1) {
                    eprintln!("lcd: {e}");
                }
            }

            "lls" => {
                let path = if arg1.is_empty() { "." } else { arg1 };
                match std::fs::read_dir(path) {
                    Ok(entries) => {
                        for entry in entries.flatten() {
                            let meta = entry.metadata().ok();
                            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                            let name = entry.file_name().to_string_lossy().to_string();
                            if is_dir {
                                println!("d  {:>10}  {name}/", "-");
                            } else {
                                println!("-  {:>10}  {name}", format_size(size));
                            }
                        }
                    }
                    Err(e) => eprintln!("lls: {e}"),
                }
            }

            "ls" => {
                let path = if arg1.is_empty() { "." } else { arg1 };
                sftp_channel
                    .send(&ChannelMsg::SftpListDir {
                        path: path.to_string(),
                    })
                    .await?;
                match sftp_channel.recv().await? {
                    ChannelMsg::SftpDirListing { entries } => {
                        print_listing(&entries);
                    }
                    ChannelMsg::SftpError { message } => {
                        eprintln!("ls: {message}");
                    }
                    other => eprintln!("ls: unexpected response: {other:?}"),
                }
            }

            "cd" => {
                if arg1.is_empty() {
                    eprintln!("cd: missing path");
                } else {
                    sftp_channel
                        .send(&ChannelMsg::SftpRealpath {
                            path: arg1.to_string(),
                        })
                        .await?;
                    match sftp_channel.recv().await? {
                        ChannelMsg::SftpOk { message } => {
                            remote_cwd = message;
                        }
                        ChannelMsg::SftpError { message } => {
                            eprintln!("cd: {message}");
                        }
                        other => eprintln!("cd: unexpected: {other:?}"),
                    }
                }
            }

            "stat" => {
                if arg1.is_empty() {
                    eprintln!("stat: missing path");
                } else {
                    sftp_channel
                        .send(&ChannelMsg::SftpStat {
                            path: arg1.to_string(),
                        })
                        .await?;
                    match sftp_channel.recv().await? {
                        ChannelMsg::SftpStatResult {
                            path,
                            size,
                            mode,
                            mtime,
                            is_dir,
                            ..
                        } => {
                            println!("  Path: {path}");
                            println!("  Type: {}", if is_dir { "directory" } else { "file" });
                            println!("  Size: {}", format_size(size));
                            println!("  Mode: {mode:04o}");
                            if mtime > 0 {
                                println!("  Modified: {mtime}");
                            }
                        }
                        ChannelMsg::SftpError { message } => {
                            eprintln!("stat: {message}");
                        }
                        other => eprintln!("stat: unexpected: {other:?}"),
                    }
                }
            }

            "mkdir" => {
                if arg1.is_empty() {
                    eprintln!("mkdir: missing path");
                } else {
                    sftp_channel
                        .send(&ChannelMsg::SftpMkdir {
                            path: arg1.to_string(),
                            mode: 0o755,
                        })
                        .await?;
                    match sftp_channel.recv().await? {
                        ChannelMsg::SftpOk { .. } => {}
                        ChannelMsg::SftpError { message } => eprintln!("mkdir: {message}"),
                        other => eprintln!("mkdir: unexpected: {other:?}"),
                    }
                }
            }

            "rm" => {
                if arg1.is_empty() {
                    eprintln!("rm: missing path");
                } else {
                    sftp_channel
                        .send(&ChannelMsg::SftpRemove {
                            path: arg1.to_string(),
                        })
                        .await?;
                    match sftp_channel.recv().await? {
                        ChannelMsg::SftpOk { .. } => {}
                        ChannelMsg::SftpError { message } => eprintln!("rm: {message}"),
                        other => eprintln!("rm: unexpected: {other:?}"),
                    }
                }
            }

            "rename" => {
                if arg1.is_empty() || arg2.is_empty() {
                    eprintln!("rename: usage: rename old new");
                } else {
                    sftp_channel
                        .send(&ChannelMsg::SftpRename {
                            old_path: arg1.to_string(),
                            new_path: arg2.to_string(),
                        })
                        .await?;
                    match sftp_channel.recv().await? {
                        ChannelMsg::SftpOk { .. } => {}
                        ChannelMsg::SftpError { message } => eprintln!("rename: {message}"),
                        other => eprintln!("rename: unexpected: {other:?}"),
                    }
                }
            }

            "get" => {
                if arg1.is_empty() {
                    eprintln!("get: missing remote path");
                } else {
                    let remote_file = if arg1.starts_with('/') || arg1.starts_with('~') {
                        arg1.to_string()
                    } else {
                        format!("{}/{}", remote_cwd.trim_end_matches('/'), arg1)
                    };
                    let local_file = if arg2.is_empty() {
                        Path::new(arg1)
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| arg1.to_string())
                    } else {
                        arg2.to_string()
                    };

                    match do_download(&conn, &remote_file, &local_file).await {
                        Ok(size) => println!("{local_file} ({size} bytes)"),
                        Err(e) => eprintln!("get: {e}"),
                    }
                }
            }

            "put" => {
                if arg1.is_empty() {
                    eprintln!("put: missing local path");
                } else {
                    let local_path = PathBuf::from(arg1);
                    let remote_file = if arg2.is_empty() {
                        let name = local_path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| arg1.to_string());
                        format!("{}/{}", remote_cwd.trim_end_matches('/'), name)
                    } else if arg2.starts_with('/') || arg2.starts_with('~') {
                        arg2.to_string()
                    } else {
                        format!("{}/{}", remote_cwd.trim_end_matches('/'), arg2)
                    };

                    match do_upload(&conn, &local_path, &remote_file).await {
                        Ok(size) => println!("{arg1} ({size} bytes)"),
                        Err(e) => eprintln!("put: {e}"),
                    }
                }
            }

            _ => {
                eprintln!("unknown command: {cmd} (type 'help' for commands)");
            }
        }
    }

    sftp_channel.send(&ChannelMsg::Close).await.ok();
    Ok(())
}

async fn do_download(
    conn: &quinn::Connection,
    remote_path: &str,
    local_path: &str,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let mut channel = Channel::open(
        conn,
        ChannelType::FileTransfer {
            direction: TransferDirection::Download,
            path: remote_path.to_string(),
        },
    )
    .await?;

    match channel.recv().await? {
        ChannelMsg::ChannelOpenConfirm => {}
        ChannelMsg::ChannelOpenFailure { description, .. } => {
            return Err(description.into());
        }
        other => return Err(format!("unexpected: {other:?}").into()),
    }

    match channel.recv().await? {
        ChannelMsg::FileResult {
            success: false,
            message,
        } => {
            return Err(message.into());
        }
        ChannelMsg::FileHeader {
            size, mode, ..
        } => {
            use std::io::Write;
            use std::os::unix::fs::PermissionsExt;

            let mut file = std::fs::File::create(local_path)?;
            let mut written: u64 = 0;

            loop {
                match channel.recv().await? {
                    ChannelMsg::Data { payload } => {
                        file.write_all(&payload)?;
                        written += payload.len() as u64;
                    }
                    ChannelMsg::Eof => break,
                    other => return Err(format!("unexpected: {other:?}").into()),
                }
            }

            file.flush()?;
            drop(file);
            std::fs::set_permissions(local_path, std::fs::Permissions::from_mode(mode))?;

            channel
                .send(&ChannelMsg::FileResult {
                    success: true,
                    message: String::new(),
                })
                .await?;

            if written != size {
                eprintln!("warning: expected {size} bytes, got {written}");
            }

            Ok(written)
        }
        other => Err(format!("unexpected: {other:?}").into()),
    }
}

async fn do_upload(
    conn: &quinn::Connection,
    local_path: &Path,
    remote_path: &str,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Read;

    let meta = std::fs::metadata(local_path)?;
    let size = meta.len();
    let mode = meta.mode();

    let mut channel = Channel::open(
        conn,
        ChannelType::FileTransfer {
            direction: TransferDirection::Upload,
            path: remote_path.to_string(),
        },
    )
    .await?;

    match channel.recv().await? {
        ChannelMsg::ChannelOpenConfirm => {}
        ChannelMsg::ChannelOpenFailure { description, .. } => {
            return Err(description.into());
        }
        other => return Err(format!("unexpected: {other:?}").into()),
    }

    channel
        .send(&ChannelMsg::FileHeader {
            path: remote_path.to_string(),
            size,
            mode,
            mtime: 0,
            atime: 0,
        })
        .await?;

    let mut file = std::fs::File::open(local_path)?;
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
                return Err(format!("upload failed: {message}").into());
            }
        }
        other => return Err(format!("unexpected: {other:?}").into()),
    }

    Ok(size)
}

fn print_listing(entries: &[ManifestEntry]) {
    for entry in entries {
        let type_char = if entry.is_dir { 'd' } else { '-' };
        let perms = format_perms(entry.mode);
        let size = if entry.is_dir {
            "-".to_string()
        } else {
            format_size(entry.size)
        };
        let name = if entry.is_dir {
            format!("{}/", entry.path)
        } else {
            entry.path.clone()
        };
        println!("{type_char}{perms}  {:>8}  {name}", size);
    }
}

fn format_perms(mode: u32) -> String {
    let mut s = String::with_capacity(9);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1}G", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1}M", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}")
    }
}
