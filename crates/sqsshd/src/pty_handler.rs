use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;

use nix::pty::openpty;
use nix::unistd;
use sqssh_core::protocol::ChannelMsg;
use sqssh_core::stream::Channel;
use tokio::io::unix::AsyncFd;

/// Look up a system user by name. Returns (uid, gid, home, shell).
pub fn lookup_user(username: &str) -> Result<(u32, u32, String, String), Box<dyn std::error::Error + Send + Sync>> {
    let user = nix::unistd::User::from_name(username)?
        .ok_or_else(|| format!("user '{username}' not found"))?;
    let shell = user
        .shell
        .to_str()
        .unwrap_or("/bin/sh")
        .to_string();
    let home = user
        .dir
        .to_str()
        .unwrap_or("/")
        .to_string();
    Ok((user.uid.as_raw(), user.gid.as_raw(), home, shell))
}

/// Apply user switching in pre_exec. Must be called inside an unsafe pre_exec closure.
unsafe fn switch_user(uid: u32, gid: u32, username: &str) -> std::io::Result<()> {
    // setgid first (while we're still root)
    if libc::setgid(gid) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // initgroups
    let c_username = std::ffi::CString::new(username).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid username")
    })?;
    // On macOS initgroups takes c_int, on Linux it takes gid_t (u32)
    #[cfg(target_os = "macos")]
    let group_arg = gid as libc::c_int;
    #[cfg(not(target_os = "macos"))]
    let group_arg = gid;
    if libc::initgroups(c_username.as_ptr(), group_arg) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // setuid last
    if libc::setuid(uid) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Run a command (exec request) as the specified user.
pub async fn run_exec(
    channel: &mut Channel,
    username: &str,
    command: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (uid, gid, home, shell) = lookup_user(username)?;
    let username_owned = username.to_string();

    let mut cmd = tokio::process::Command::new(&shell);
    cmd.arg("-c").arg(command);
    cmd.env("HOME", &home);
    cmd.env("USER", &username_owned);
    cmd.env("LOGNAME", &username_owned);
    cmd.current_dir(&home);

    unsafe {
        cmd.pre_exec(move || switch_user(uid, gid, &username_owned));
    }

    let output = cmd.output().await?;

    channel
        .send(&ChannelMsg::Data {
            payload: output.stdout,
        })
        .await?;

    if !output.stderr.is_empty() {
        channel
            .send(&ChannelMsg::ExtendedData {
                data_type: 1,
                payload: output.stderr,
            })
            .await?;
    }

    let code = output.status.code().unwrap_or(1) as u32;
    channel.send(&ChannelMsg::ExitStatus { code }).await?;
    channel.send(&ChannelMsg::Eof).await?;
    channel.send(&ChannelMsg::Close).await?;
    Ok(())
}

/// Check if ~/.hushlogin exists for the user (no symlink following).
fn has_hushlogin(home: &str) -> bool {
    std::fs::symlink_metadata(Path::new(home).join(".hushlogin"))
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// Read and format the last login time from lastlog.
/// Returns the formatted message and updates lastlog with the current time.
fn get_and_update_lastlog(uid: u32, remote_host: &str) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        use std::fs::OpenOptions;
        use std::io::{Read, Seek, SeekFrom, Write};

        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Lastlog {
            ll_time: i64,      // time_t on x86_64 Linux
            ll_line: [u8; 32], // UT_LINESIZE
            ll_host: [u8; 256], // UT_HOSTSIZE
        }

        let entry_size = std::mem::size_of::<Lastlog>();
        let offset = (uid as u64) * (entry_size as u64);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/var/log/lastlog")
            .ok()?;

        // Read old entry
        let mut old: Lastlog = unsafe { std::mem::zeroed() };
        file.seek(SeekFrom::Start(offset)).ok()?;
        let buf = unsafe {
            std::slice::from_raw_parts_mut(
                &mut old as *mut Lastlog as *mut u8,
                entry_size,
            )
        };
        let _ = file.read(buf);

        let msg = if old.ll_time > 0 {
            let time_str = {
                let tm = unsafe { libc::localtime(&old.ll_time as *const i64) };
                if tm.is_null() {
                    "unknown time".to_string()
                } else {
                    let mut buf = [0u8; 64];
                    let len = unsafe {
                        libc::strftime(
                            buf.as_mut_ptr() as *mut libc::c_char,
                            buf.len(),
                            b"%a %b %e %H:%M:%S %Y\0".as_ptr() as *const libc::c_char,
                            tm,
                        )
                    };
                    String::from_utf8_lossy(&buf[..len]).to_string()
                }
            };
            let host = std::str::from_utf8(&old.ll_host)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            if host.is_empty() {
                Some(format!("Last login: {time_str}\r\n"))
            } else {
                Some(format!("Last login: {time_str} from {host}\r\n"))
            }
        } else {
            None
        };

        // Write new entry
        let now = unsafe { libc::time(std::ptr::null_mut()) };
        let mut new_entry: Lastlog = unsafe { std::mem::zeroed() };
        new_entry.ll_time = now;
        // Set line to "sqssh"
        let line = b"sqssh";
        new_entry.ll_line[..line.len()].copy_from_slice(line);
        // Set host
        let host_bytes = remote_host.as_bytes();
        let copy_len = host_bytes.len().min(255);
        new_entry.ll_host[..copy_len].copy_from_slice(&host_bytes[..copy_len]);

        let _ = file.seek(SeekFrom::Start(offset));
        let buf = unsafe {
            std::slice::from_raw_parts(
                &new_entry as *const Lastlog as *const u8,
                entry_size,
            )
        };
        let _ = file.write_all(buf);

        msg
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (uid, remote_host);
        None
    }
}

/// Read /etc/motd contents if the file exists.
fn read_motd() -> Option<String> {
    let content = std::fs::read_to_string("/etc/motd").ok()?;
    if content.is_empty() {
        return None;
    }
    // Convert \n to \r\n for PTY
    Some(content.replace('\n', "\r\n"))
}

/// Spawn a shell attached to a PTY and relay I/O over the channel.
pub async fn run_shell(
    channel: &mut Channel,
    username: &str,
    remote_host: &str,
    term: &str,
    cols: u16,
    rows: u16,
    print_motd: bool,
    print_last_log: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (uid, gid, home, shell) = lookup_user(username)?;

    // Print login messages before spawning the shell (like sshd does)
    if !has_hushlogin(&home) {
        if print_last_log {
            if let Some(last_login_msg) = get_and_update_lastlog(uid, remote_host) {
                channel
                    .send(&ChannelMsg::Data {
                        payload: last_login_msg.into_bytes(),
                    })
                    .await?;
            }
        }

        if print_motd {
            if let Some(motd) = read_motd() {
                channel
                    .send(&ChannelMsg::Data {
                        payload: motd.into_bytes(),
                    })
                    .await?;
            }
        }
    }

    let pty = openpty(None, None)?;
    let master_fd = pty.master;
    let slave_fd = pty.slave;

    // Set window size
    set_winsize(master_fd.as_raw_fd(), cols, rows);

    // Spawn the shell as the target user
    let slave_raw = slave_fd.as_raw_fd();
    let username_owned = username.to_string();

    let mut cmd = std::process::Command::new(&shell);
    cmd.arg("-l");
    cmd.env("TERM", term);
    cmd.env("HOME", &home);
    cmd.env("USER", &username_owned);
    cmd.env("LOGNAME", &username_owned);
    cmd.env("SHELL", &shell);
    cmd.current_dir(&home);
    cmd.stdin(unsafe { Stdio::from_raw_fd(slave_raw) });
    cmd.stdout(unsafe { Stdio::from_raw_fd(slave_raw) });
    cmd.stderr(unsafe { Stdio::from_raw_fd(slave_raw) });

    unsafe {
        cmd.pre_exec(move || {
            switch_user(uid, gid, &username_owned)?;
            unistd::setsid().map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            libc::ioctl(slave_raw, libc::TIOCSCTTY as libc::c_ulong, 0);
            Ok(())
        });
    }

    let mut child = cmd.spawn()?;
    drop(slave_fd); // Close slave in parent

    // Set master fd non-blocking for async I/O
    let master_raw = master_fd.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(master_raw, libc::F_GETFL);
        libc::fcntl(master_raw, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let master_afd = AsyncFd::new(master_fd)?;

    // Relay loop: PTY ↔ channel
    loop {
        tokio::select! {
            // PTY → channel
            ready = master_afd.readable() => {
                let mut guard = ready?;
                match guard.try_io(|inner| {
                    let mut buf = [0u8; 8192];
                    let n = unsafe {
                        libc::read(
                            inner.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        Err(std::io::Error::last_os_error())
                    } else if n == 0 {
                        Ok(Vec::new())
                    } else {
                        Ok(buf[..n as usize].to_vec())
                    }
                }) {
                    Ok(Ok(data)) if data.is_empty() => break,
                    Ok(Ok(data)) => {
                        if channel.send(&ChannelMsg::Data { payload: data }).await.is_err() {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!("PTY read error: {e}");
                        break;
                    }
                    Err(_would_block) => continue,
                }
            }

            // Channel → PTY
            msg = channel.recv() => {
                match msg {
                    Ok(ChannelMsg::Data { payload }) => {
                        // Write to PTY master
                        let fd = master_afd.get_ref().as_raw_fd();
                        let mut offset = 0;
                        while offset < payload.len() {
                            let n = unsafe {
                                libc::write(
                                    fd,
                                    payload[offset..].as_ptr() as *const libc::c_void,
                                    payload.len() - offset,
                                )
                            };
                            if n <= 0 {
                                break;
                            }
                            offset += n as usize;
                        }
                    }
                    Ok(ChannelMsg::WindowChange { cols, rows }) => {
                        set_winsize(master_afd.get_ref().as_raw_fd(), cols as u16, rows as u16);
                    }
                    Ok(ChannelMsg::Eof) | Ok(ChannelMsg::Close) | Err(_) => break,
                    Ok(_) => {} // Ignore other messages
                }
            }
        }
    }

    // Wait for child and send exit status
    let status = child.wait()?;
    let code = status.code().unwrap_or(1) as u32;
    let _ = channel.send(&ChannelMsg::ExitStatus { code }).await;
    let _ = channel.send(&ChannelMsg::Eof).await;
    let _ = channel.send(&ChannelMsg::Close).await;

    Ok(())
}

fn set_winsize(fd: i32, cols: u16, rows: u16) {
    let winsize = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        libc::ioctl(fd, libc::TIOCSWINSZ, &winsize as *const _);
    }
}
