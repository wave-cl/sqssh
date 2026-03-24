//! File descriptor passing over Unix domain sockets via SCM_RIGHTS.

use std::io;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;

/// Send file descriptors and data over a Unix domain socket.
pub fn send_fds(socket: &UnixStream, fds: &[RawFd], data: &[u8]) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd_bytes = unsafe {
        std::slice::from_raw_parts(fds.as_ptr() as *const u8, fds.len() * std::mem::size_of::<RawFd>())
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE((fds.len() * std::mem::size_of::<RawFd>()) as u32) } as usize;

    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut iov = libc::iovec {
        iov_base: if data.is_empty() {
            // sendmsg requires at least 1 byte of data
            b"\0".as_ptr() as *mut libc::c_void
        } else {
            data.as_ptr() as *mut libc::c_void
        },
        iov_len: if data.is_empty() { 1 } else { data.len() },
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() {
        return Err(io::Error::new(io::ErrorKind::Other, "CMSG_FIRSTHDR returned null"));
    }

    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN((fds.len() * std::mem::size_of::<RawFd>()) as u32) as _;
        std::ptr::copy_nonoverlapping(
            fd_bytes.as_ptr(),
            libc::CMSG_DATA(cmsg),
            fd_bytes.len(),
        );
    }

    let ret = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, 0) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Receive file descriptors and data from a Unix domain socket.
/// Returns (fds, data).
pub fn recv_fds(socket: &UnixStream, max_fds: usize) -> io::Result<(Vec<RawFd>, Vec<u8>)> {
    use std::os::unix::io::AsRawFd;

    let cmsg_space = unsafe {
        libc::CMSG_SPACE((max_fds * std::mem::size_of::<RawFd>()) as u32)
    } as usize;

    let mut cmsg_buf = vec![0u8; cmsg_space];
    let mut data_buf = vec![0u8; 65536]; // max data payload

    let mut iov = libc::iovec {
        iov_base: data_buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: data_buf.len(),
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    let ret = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let data_len = ret as usize;
    data_buf.truncate(data_len);

    let mut fds = Vec::new();

    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let fd_data = libc::CMSG_DATA(cmsg);
                let fd_len = (*cmsg).cmsg_len as usize
                    - libc::CMSG_LEN(0) as usize;
                let num_fds = fd_len / std::mem::size_of::<RawFd>();

                for i in 0..num_fds {
                    let fd = std::ptr::read_unaligned(
                        fd_data.add(i * std::mem::size_of::<RawFd>()) as *const RawFd,
                    );
                    fds.push(fd);
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((fds, data_buf))
}
