extern crate libc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
extern crate libgcrypt_sys as ffi;

use std::ffi::CString;
use std::ptr;
use std::result;
use std::sync::{Mutex, MutexGuard};

pub use error::{Error, Result};
pub use buffer::Buffer;

#[macro_use]
mod utils;
mod buffer;
pub mod error;
pub mod rand;
pub mod cipher;
pub mod digest;
pub mod mac;

lazy_static! {
    static ref CONTROL_LOCK: Mutex<()> = Mutex::new(());
}

pub struct Initializer {
    _lock: MutexGuard<'static, ()>,
}

impl Initializer {
    pub fn check_version<S: Into<String>>(&mut self, version: S) -> bool {
        let version = match CString::new(version.into()) {
            Ok(v) => v,
            Err(..) => return false,
        };
        unsafe {
            !ffi::gcry_check_version(version.as_ptr()).is_null()
        }
    }

    pub fn enable_quick_random(&mut self) -> &mut Self {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_ENABLE_QUICK_RANDOM, 0);
        }
        self
    }

    pub fn disable_secmem(&mut self) -> &mut Self {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_DISABLE_SECMEM, 0);
        }
        self
    }

    pub fn enable_secmem(&mut self, amt: usize) -> Result<&mut Self> {
        unsafe {
            return_err!(ffi::gcry_control(ffi::GCRYCTL_INIT_SECMEM, amt as libc::c_int));
        }
        Ok(self)
    }

    pub fn finish(self) -> Token {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED, 0);
            Token
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Token;

impl Token {
    pub fn version(&self) -> &'static str {
        unsafe {
            utils::from_cstr(ffi::gcry_check_version(ptr::null())).unwrap()
        }
    }
}

pub fn is_initialized() -> bool {
    unsafe {
        ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED_P, 0) != 0
    }
}

pub fn init() -> result::Result<Initializer, Token> {
    let lock = CONTROL_LOCK.lock().unwrap();
    if !is_initialized() {
        unsafe {
            if cfg!(unix) {
                ffi::gcry_control(ffi::GCRYCTL_SET_THREAD_CBS, &ffi::gcry_threads_pthread);
            }
            ffi::gcry_check_version(ptr::null());
        }
        Ok(Initializer { _lock: lock })
    } else {
        Err(Token)
    }
}
