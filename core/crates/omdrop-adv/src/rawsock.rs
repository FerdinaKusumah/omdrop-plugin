//! A bound `AF_PACKET`/`SOCK_RAW` socket: whole Ethernet frames in and out of
//! one interface. Needs `CAP_NET_RAW`; the supervisor runs these as root.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// `ETH_P_ALL`: every protocol, including our own outgoing frames.
pub const ETH_P_ALL: u16 = 0x0003;

pub struct PacketSocket {
    fd: OwnedFd,
}

impl PacketSocket {
    /// Open a raw packet socket for `protocol` (host order; 0 receives
    /// nothing, for a send-only socket) and bind it to `iface`.
    pub fn open(iface: &str, protocol: u16) -> io::Result<Self> {
        let name = CString::new(iface).map_err(|_| io::Error::from_raw_os_error(libc::ENODEV))?;
        // SAFETY: `name` is a valid NUL-terminated string that outlives the call.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error());
        }
        let proto_be = protocol.to_be();
        // SAFETY: plain syscall with constant arguments; the result is checked.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                i32::from(proto_be),
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: sockaddr_ll is plain old data; all-zero is a valid value.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = proto_be;
        addr.sll_ifindex =
            i32::try_from(index).map_err(|_| io::Error::from_raw_os_error(libc::ENODEV))?;
        // SAFETY: `addr` is a valid sockaddr_ll and the length passed is its size.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_ll).cast(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PacketSocket { fd })
    }

    /// Send one whole frame out of the bound interface, retrying on EINTR.
    pub fn send(&self, frame: &[u8]) -> io::Result<usize> {
        loop {
            // SAFETY: `frame` is a valid readable buffer of the length passed.
            let n =
                unsafe { libc::send(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
            match usize::try_from(n) {
                Ok(n) => return Ok(n),
                Err(_) => {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
            }
        }
    }

    /// Receive one frame (truncated to `buf`), retrying on EINTR.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: `buf` is a valid writable buffer of the length passed.
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            match usize::try_from(n) {
                Ok(n) => return Ok(n),
                Err(_) => {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
            }
        }
    }
}

/// An OS error the way Python prints `OSError`: `[Errno 100] Network is down`.
pub fn os_error_text(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(code) => {
            let text = err.to_string();
            let suffix = format!(" (os error {code})");
            let text = text.strip_suffix(&suffix).unwrap_or(&text);
            format!("[Errno {code}] {text}")
        }
        None => err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_errors_read_like_python() {
        let err = io::Error::from_raw_os_error(libc::ENETDOWN);
        assert_eq!(os_error_text(&err), "[Errno 100] Network is down");
    }

    #[test]
    fn unknown_interface_fails_before_any_socket() {
        let err = PacketSocket::open("omdrop-nope0", 0).err().unwrap();
        assert_eq!(err.raw_os_error(), Some(libc::ENODEV));
    }
}
