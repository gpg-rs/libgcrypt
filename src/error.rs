use std::error;
use std::ffi::NulError;
use std::fmt;
use std::io::{self, ErrorKind};
use std::result;

use libc;
use ffi;

const TMPBUF_SZ: usize = 0x0400;

pub use ffi::errors::*;

use utils;

pub type ErrorCode = ffi::gcry_err_code_t;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Error {
    err: ffi::gcry_error_t,
}

impl Error {
    pub fn new(err: ffi::gcry_error_t) -> Error {
        Error { err: err }
    }

    pub fn raw(&self) -> ffi::gcry_error_t {
        self.err
    }

    pub fn from_source(source: ffi::gcry_err_source_t, code: ErrorCode) -> Error {
        Error::new(ffi::gcry_err_make(source, code))
    }

    pub fn from_code(code: ErrorCode) -> Error {
        Error::from_source(ffi::GPG_ERR_SOURCE_USER_1, code)
    }

    pub fn last_os_error() -> Error {
        unsafe {
            Error::new(ffi::gcry_error_from_syserror())
        }
    }

    pub fn from_errno(code: i32) -> Error {
        unsafe {
            Error::new(ffi::gcry_error_from_errno(code as libc::c_int))
        }
    }

    pub fn to_errno(&self) -> i32 {
        unsafe {
            ffi::gcry_err_code_to_errno(self.code())
        }
    }

    pub fn code(&self) -> ErrorCode {
        ffi::gcry_err_code(self.err)
    }

    pub fn source(&self) -> Option<&'static str> {
        unsafe {
            utils::from_cstr(ffi::gcry_strsource(self.err))
        }
    }

    pub fn description(&self) -> String {
        let mut buf = [0 as libc::c_char; TMPBUF_SZ];
        let p = buf.as_mut_ptr();
        unsafe {
            if ffi::gcry_strerror_r(self.err, p, buf.len() as libc::size_t) < 0 {
                panic!("gcry_strerror_r failure")
            }
            utils::from_cstr(p).unwrap().to_owned()
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "gcry error"
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{} (gcry error {})", self.description(), self.code())
    }
}

impl From<NulError> for Error {
    fn from(_: NulError) -> Error {
        Error::from_code(ffi::GPG_ERR_INV_VALUE)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        let code = match err.kind() {
            ErrorKind::NotFound => GPG_ERR_ENOENT,
            ErrorKind::PermissionDenied => GPG_ERR_EACCES,
            ErrorKind::ConnectionRefused => GPG_ERR_ECONNREFUSED,
            ErrorKind::ConnectionReset => GPG_ERR_ECONNRESET,
            ErrorKind::ConnectionAborted => GPG_ERR_ECONNABORTED,
            ErrorKind::NotConnected => GPG_ERR_ENOTCONN,
            ErrorKind::AddrInUse => GPG_ERR_EADDRINUSE,
            ErrorKind::AddrNotAvailable => GPG_ERR_EADDRNOTAVAIL,
            ErrorKind::BrokenPipe => GPG_ERR_EPIPE,
            ErrorKind::AlreadyExists => GPG_ERR_EEXIST,
            ErrorKind::WouldBlock => GPG_ERR_EWOULDBLOCK,
            ErrorKind::InvalidInput => GPG_ERR_EINVAL,
            ErrorKind::TimedOut => GPG_ERR_ETIMEDOUT,
            ErrorKind::Interrupted => GPG_ERR_EINTR,
            _ => GPG_ERR_EIO,

        };
        Error::from_code(code)
    }
}

impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        let kind = match self.code() {
            GPG_ERR_ECONNREFUSED => ErrorKind::ConnectionRefused,
            GPG_ERR_ECONNRESET => ErrorKind::ConnectionReset,
            GPG_ERR_EPERM | GPG_ERR_EACCES => ErrorKind::PermissionDenied,
            GPG_ERR_EPIPE => ErrorKind::BrokenPipe,
            GPG_ERR_ENOTCONN => ErrorKind::NotConnected,
            GPG_ERR_ECONNABORTED => ErrorKind::ConnectionAborted,
            GPG_ERR_EADDRNOTAVAIL => ErrorKind::AddrNotAvailable,
            GPG_ERR_EADDRINUSE => ErrorKind::AddrInUse,
            GPG_ERR_ENOENT => ErrorKind::NotFound,
            GPG_ERR_EINTR => ErrorKind::Interrupted,
            GPG_ERR_EINVAL => ErrorKind::InvalidInput,
            GPG_ERR_ETIMEDOUT => ErrorKind::TimedOut,
            GPG_ERR_EEXIST => ErrorKind::AlreadyExists,
            x if x == GPG_ERR_EAGAIN || x == GPG_ERR_EWOULDBLOCK =>
                ErrorKind::WouldBlock,
            _ => ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

pub type Result<T> = result::Result<T, Error>;
