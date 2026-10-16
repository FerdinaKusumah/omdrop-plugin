//! Errors as the Python sender reported them.
//!
//! airdrop-send.py logged every failed request as `%r` of the Python
//! exception (`ASK failed: TimeoutError('timed out')`), `omdrop` shows the text
//! after `failed: ` to the person sending, and `--discover-only` names only the
//! exception class (`[::1]:8771: no answer (TimeoutError)`). Every failure here
//! is an `io::Error`; [`PyErr::from_io`] gives it the Python class and repr.

use std::fmt;
use std::io;

use crate::pyfmt::str_repr;

/// An error with the Python exception class it corresponds to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyErr {
    /// `TimeoutError`, `ConnectionRefusedError`, `SSLError`, ...
    pub class: &'static str,
    /// `TimeoutError('timed out')`, `ConnectionRefusedError(111, 'Connection refused')`.
    pub repr: String,
}

impl PyErr {
    /// An exception with one message argument.
    pub fn new(class: &'static str, message: &str) -> PyErr {
        PyErr {
            class,
            repr: format!("{class}({})", str_repr(message)),
        }
    }

    /// As an `io::Error` that [`PyErr::from_io`] turns back into this.
    pub fn into_io(self) -> io::Error {
        io::Error::other(self)
    }

    /// The Python exception a failed socket, TLS or HTTP operation raised.
    pub fn from_io(e: &io::Error) -> PyErr {
        if let Some(inner) = e.get_ref() {
            if let Some(py) = inner.downcast_ref::<PyErr>() {
                return py.clone();
            }
            if let Some(tls) = inner.downcast_ref::<rustls::Error>() {
                return PyErr::new("SSLError", &tls.to_string());
            }
        }
        match (e.kind(), e.raw_os_error()) {
            // A socket timeout is EAGAIN on Linux; connect_timeout's is TimedOut
            // with no errno. Python raises TimeoutError('timed out') for both.
            (io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut, None | Some(libc::EAGAIN)) => {
                PyErr::new("TimeoutError", "timed out")
            }
            (io::ErrorKind::UnexpectedEof, None) => PyErr::new(
                "RemoteDisconnected",
                "Remote end closed connection without response",
            ),
            (_, Some(errno)) => {
                let class = match errno {
                    libc::ECONNREFUSED => "ConnectionRefusedError",
                    libc::ECONNRESET => "ConnectionResetError",
                    libc::ECONNABORTED => "ConnectionAbortedError",
                    libc::EPIPE | libc::ESHUTDOWN => "BrokenPipeError",
                    libc::ETIMEDOUT => "TimeoutError",
                    libc::ENOENT => "FileNotFoundError",
                    libc::EACCES | libc::EPERM => "PermissionError",
                    libc::EISDIR => "IsADirectoryError",
                    libc::ENOTDIR => "NotADirectoryError",
                    libc::EINTR => "InterruptedError",
                    _ => "OSError",
                };
                let text = io::Error::from_raw_os_error(errno).to_string();
                let text = text.split(" (os error").next().unwrap_or(&text);
                PyErr {
                    class,
                    repr: format!("{class}({errno}, {})", str_repr(text)),
                }
            }
            _ => PyErr::new("OSError", &e.to_string()),
        }
    }
}

impl fmt::Display for PyErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.repr)
    }
}

impl std::error::Error for PyErr {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_errors_read_like_python_exceptions() {
        let timeout = io::Error::from_raw_os_error(libc::EAGAIN);
        assert_eq!(PyErr::from_io(&timeout).repr, "TimeoutError('timed out')");
        let refused = io::Error::from_raw_os_error(libc::ECONNREFUSED);
        let py = PyErr::from_io(&refused);
        assert_eq!(py.class, "ConnectionRefusedError");
        assert_eq!(py.repr, "ConnectionRefusedError(111, 'Connection refused')");
        let ours = PyErr::new("RemoteDisconnected", "gone").into_io();
        assert_eq!(PyErr::from_io(&ours).repr, "RemoteDisconnected('gone')");
        let connect = io::Error::new(io::ErrorKind::TimedOut, "connection timed out");
        assert_eq!(PyErr::from_io(&connect).class, "TimeoutError");
    }
}
