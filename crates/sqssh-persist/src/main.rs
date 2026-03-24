//! sqssh-persist: holds PTY master file descriptors during sqsshd restarts.
//!
//! Protocol:
//! 1. sqsshd connects and sends fds + serialized PersistPayload via sendmsg
//! 2. sqssh-persist holds the fds in memory
//! 3. New sqsshd connects and requests recovery
//! 4. sqssh-persist sends fds + payload back via sendmsg
//! 5. sqssh-persist exits

use std::os::unix::io::RawFd;
use std::os::unix::net::UnixListener;
use std::path::Path;

use sqssh_core::fdpass;
use sqssh_core::persist::PersistPayload;

const SOCKET_PATH: &str = "/var/run/sqssh/persist.sock";
const TIMEOUT_SECS: u64 = 120; // exit if no recovery within 2 minutes

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .init();

    if let Err(e) = run() {
        eprintln!("sqssh-persist: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = Path::new(SOCKET_PATH);

    // Remove stale socket
    std::fs::remove_file(socket_path).ok();

    let listener = UnixListener::bind(socket_path)?;
    tracing::info!("listening on {SOCKET_PATH}");

    // Phase 1: receive fds from sqsshd
    tracing::info!("waiting for sqsshd to send sessions...");
    let (stream, _) = listener.accept()?;
    let (fds, data) = fdpass::recv_fds(&stream, 256)?;
    drop(stream);

    let payload = PersistPayload::decode(&data)
        .map_err(|e| format!("failed to decode payload: {e}"))?;

    tracing::info!(
        "received {} session(s) with {} fd(s)",
        payload.sessions.len(),
        fds.len()
    );

    for (i, session) in payload.sessions.iter().enumerate() {
        tracing::info!(
            "  session {}: user={}, pid={}, term={}, fd={}",
            i,
            session.username,
            session.child_pid,
            session.term,
            fds.get(i).map(|f| f.to_string()).unwrap_or_else(|| "?".into()),
        );
    }

    // Phase 2: wait for new sqsshd to connect and reclaim
    listener.set_nonblocking(false)?;
    let timeout = std::time::Duration::from_secs(TIMEOUT_SECS);

    tracing::info!("holding fds, waiting for new sqsshd (timeout: {TIMEOUT_SECS}s)...");

    // Set accept timeout
    use std::os::unix::io::AsRawFd;
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    match listener.accept() {
        Ok((stream, _)) => {
            tracing::info!("new sqsshd connected, sending sessions back");
            fdpass::send_fds(&stream, &fds, &data)?;
            drop(stream);
            tracing::info!("sessions handed off successfully");
        }
        Err(e) => {
            tracing::warn!("timeout waiting for new sqsshd: {e}");
            tracing::warn!("closing {} orphaned session(s)", payload.sessions.len());
            // Close the fds — this will cause shells to get SIGHUP
            for fd in &fds {
                unsafe { libc::close(*fd); }
            }
        }
    }

    // Cleanup
    std::fs::remove_file(socket_path).ok();
    tracing::info!("exiting");
    Ok(())
}
