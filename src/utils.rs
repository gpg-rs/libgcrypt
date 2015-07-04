use std::ffi::CStr;
use std::str;

use libc;

macro_rules! try_opt {
    ($e:expr) => (match $e { Some(v) => v, None => return None });
}

macro_rules! return_err {
    ($e:expr) => (match $e {
        $crate::error::GPG_ERR_NO_ERROR => (),
        err => return Err($crate::Error::new(err)),
    });
}

pub unsafe fn from_cstr<'a>(s: *const libc::c_char) -> Option<&'a str> {
    if !s.is_null() {
        str::from_utf8(CStr::from_ptr(s).to_bytes()).ok()
    } else {
        None
    }
}
