use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::Stdio;

use nix::pty::openpty;
use nix::unistd;
use sqssh_core::protocol::ChannelMsg;
use sqssh_core::stream::Channel;
use tokio::io::unix::AsyncFd;

/// Spawn a shell attached to a PTY and relay I/O over the channel.
pub async fn run_shell(
    channel: &mut Channel,
    term: &str,
    cols: u16,
    rows: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let pty = openpty(None, None)?;
    let master_fd = pty.master;
    let slave_fd = pty.slave;

    // Set window size
    set_winsize(master_fd.as_raw_fd(), cols, rows);

    // Spawn the shell
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let slave_raw = slave_fd.as_raw_fd();

    let mut cmd = std::process::Command::new(&shell);
    cmd.arg("-l");
    cmd.env("TERM", term);
    cmd.stdin(unsafe { Stdio::from_raw_fd(slave_raw) });
    cmd.stdout(unsafe { Stdio::from_raw_fd(slave_raw) });
    cmd.stderr(unsafe { Stdio::from_raw_fd(slave_raw) });

    unsafe {
        cmd.pre_exec(move || {
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
