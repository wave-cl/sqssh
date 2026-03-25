use std::io::{self, BufRead, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use clap::Parser;
use sqssh_core::client;
use sqssh_core::protocol::{ManifestEntry, RawFileHeader, SftpCmd, SftpResp, RAW_SFTP, RAW_CHUNK_SIZE};

#[derive(Parser)]
#[command(name = "sqsftp", about = "sqssh interactive file transfer", version)]
struct Cli {
    /// [user@]hostname
    destination: String,

    /// Port (UDP)
    #[arg(short = 'p', short_alias = 'P', long = "port")]
    port: Option<u16>,

    /// Identity file (private key)
    #[arg(short = 'i', long = "identity")]
    identity: Option<PathBuf>,

    /// Config file (default: ~/.sqssh/config)
    #[arg(short = 'F', long = "config")]
    config_file: Option<PathBuf>,

    /// Batch file (read commands from file instead of stdin)
    #[arg(short = 'b', long = "batch")]
    batch: Option<PathBuf>,

    /// Quiet mode
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Verbose mode
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// SSH config option (accepted for compatibility, currently ignored)
    #[arg(short = 'o', long = "option", num_args = 1)]
    option: Vec<String>,
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
        cli.config_file.as_deref(),
    )
    .await?;

    let conn = connection.conn;

    // Open raw SFTP bidi stream
    let (mut sftp_send, mut sftp_recv) = conn.open_bi().await?;
    sftp_send.write_all(&[RAW_SFTP]).await?;

    // Get initial remote cwd
    sftp_send.write_all(&SftpCmd::Realpath { path: ".".to_string() }.encode()).await?;
    let mut remote_cwd = match SftpResp::decode(&mut sftp_recv).await? {
        SftpResp::Ok { message } => message,
        _ => "~".to_string(),
    };

    // Set up input source: batch file or stdin
    let batch_input: Option<io::BufReader<std::fs::File>> = if let Some(ref batch_path) = cli.batch {
        let file = std::fs::File::open(batch_path)
            .map_err(|e| format!("cannot open batch file {}: {e}", batch_path.display()))?;
        Some(io::BufReader::new(file))
    } else {
        None
    };

    let stdin = io::stdin();
    let mut stdin_reader = stdin.lock();
    let mut batch_reader = batch_input;
    let is_batch = batch_reader.is_some();
    let _quiet = cli.quiet;

    loop {
        if !is_batch {
            print!("sftp> ");
            io::stdout().flush()?;
        }

        let mut line = String::new();
        let bytes_read = if let Some(ref mut br) = batch_reader {
            br.read_line(&mut line)?
        } else {
            stdin_reader.read_line(&mut line)?
        };
        if bytes_read == 0 {
            break;
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
                sftp_send.write_all(&SftpCmd::ListDir { path: path.to_string() }.encode()).await?;
                match SftpResp::decode(&mut sftp_recv).await? {
                    SftpResp::DirListing { entries } => print_listing(&entries),
                    SftpResp::Error { message } => eprintln!("ls: {message}"),
                    other => eprintln!("ls: unexpected response: {other:?}"),
                }
            }

            "cd" => {
                if arg1.is_empty() {
                    eprintln!("cd: missing path");
                } else {
                    sftp_send.write_all(&SftpCmd::Realpath { path: arg1.to_string() }.encode()).await?;
                    match SftpResp::decode(&mut sftp_recv).await? {
                        SftpResp::Ok { message } => remote_cwd = message,
                        SftpResp::Error { message } => eprintln!("cd: {message}"),
                        other => eprintln!("cd: unexpected: {other:?}"),
                    }
                }
            }

            "stat" => {
                if arg1.is_empty() {
                    eprintln!("stat: missing path");
                } else {
                    sftp_send.write_all(&SftpCmd::Stat { path: arg1.to_string() }.encode()).await?;
                    match SftpResp::decode(&mut sftp_recv).await? {
                        SftpResp::StatResult { path, size, mode, mtime, is_dir, .. } => {
                            println!("  Path: {path}");
                            println!("  Type: {}", if is_dir { "directory" } else { "file" });
                            println!("  Size: {}", format_size(size));
                            println!("  Mode: {mode:04o}");
                            if mtime > 0 {
                                println!("  Modified: {mtime}");
                            }
                        }
                        SftpResp::Error { message } => eprintln!("stat: {message}"),
                        other => eprintln!("stat: unexpected: {other:?}"),
                    }
                }
            }

            "mkdir" => {
                if arg1.is_empty() {
                    eprintln!("mkdir: missing path");
                } else {
                    sftp_send.write_all(&SftpCmd::Mkdir { path: arg1.to_string(), mode: 0o755 }.encode()).await?;
                    match SftpResp::decode(&mut sftp_recv).await? {
                        SftpResp::Ok { .. } => {}
                        SftpResp::Error { message } => eprintln!("mkdir: {message}"),
                        other => eprintln!("mkdir: unexpected: {other:?}"),
                    }
                }
            }

            "rm" => {
                if arg1.is_empty() {
                    eprintln!("rm: missing path");
                } else {
                    sftp_send.write_all(&SftpCmd::Remove { path: arg1.to_string() }.encode()).await?;
                    match SftpResp::decode(&mut sftp_recv).await? {
                        SftpResp::Ok { .. } => {}
                        SftpResp::Error { message } => eprintln!("rm: {message}"),
                        other => eprintln!("rm: unexpected: {other:?}"),
                    }
                }
            }

            "rename" => {
                if arg1.is_empty() || arg2.is_empty() {
                    eprintln!("rename: usage: rename old new");
                } else {
                    sftp_send.write_all(&SftpCmd::Rename {
                        old_path: arg1.to_string(),
                        new_path: arg2.to_string(),
                    }.encode()).await?;
                    match SftpResp::decode(&mut sftp_recv).await? {
                        SftpResp::Ok { .. } => {}
                        SftpResp::Error { message } => eprintln!("rename: {message}"),
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

                    // Send get command on SFTP control stream
                    sftp_send.write_all(&SftpCmd::Get { path: remote_file.clone() }.encode()).await?;

                    // Server sends file on a uni stream
                    match conn.accept_uni().await {
                        Ok(mut uni_recv) => {
                            let mut type_buf = [0u8; 1];
                            uni_recv.read_exact(&mut type_buf).await?;
                            let header = RawFileHeader::decode(&mut uni_recv).await?;

                            let mut file = std::fs::File::create(&local_file)?;
                            let mut written: u64 = 0;
                            let mut buf = vec![0u8; RAW_CHUNK_SIZE];

                            loop {
                                match uni_recv.read(&mut buf).await? {
                                    Some(n) => {
                                        file.write_all(&buf[..n])?;
                                        written += n as u64;
                                    }
                                    None => break,
                                }
                            }

                            file.flush()?;
                            drop(file);
                            std::fs::set_permissions(
                                &local_file,
                                std::fs::Permissions::from_mode(header.mode),
                            )?;

                            println!("{local_file} ({written} bytes)");
                        }
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

                    let meta = match std::fs::metadata(&local_path) {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("put: {e}");
                            continue;
                        }
                    };

                    // Notify server a put is coming
                    sftp_send.write_all(&SftpCmd::Put.encode()).await?;

                    // Send file on a uni stream
                    let mut uni_send = conn.open_uni().await?;
                    let header = RawFileHeader {
                        path: remote_file.clone(),
                        size: meta.len(),
                        mode: meta.mode(),
                        mtime: 0,
                        atime: 0,
                    };
                    uni_send.write_all(&header.encode_upload()).await?;

                    let mut file = std::fs::File::open(&local_path)?;
                    let mut buf = vec![0u8; RAW_CHUNK_SIZE];
                    loop {
                        let n = std::io::Read::read(&mut file, &mut buf)?;
                        if n == 0 { break; }
                        uni_send.write_all(&buf[..n]).await?;
                    }
                    uni_send.finish()?;

                    // Wait for server ack on sftp stream
                    match SftpResp::decode(&mut sftp_recv).await? {
                        SftpResp::Ok { .. } => println!("{arg1} ({} bytes)", meta.len()),
                        SftpResp::Error { message } => eprintln!("put: {message}"),
                        other => eprintln!("put: unexpected: {other:?}"),
                    }
                }
            }

            _ => {
                eprintln!("unknown command: {cmd} (type 'help' for commands)");
            }
        }
    }

    sftp_send.finish().ok();
    Ok(())
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
