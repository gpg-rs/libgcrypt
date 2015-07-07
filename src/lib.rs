extern crate libc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate gpg_error;
extern crate libgcrypt_sys as ffi;

use std::ffi::CString;
use std::mem;
use std::ptr;
use std::sync::{Mutex, MutexGuard};

pub use gpg_error as error;
pub use error::{Error, Result};
pub use buffer::Buffer;

#[macro_use]
mod utils;
mod buffer;
pub mod rand;
pub mod mpi;
pub mod sexp;
pub mod pkey;
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

    pub fn finish(self) {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED, 0);
        }
    }
}

pub fn is_initialized() -> bool {
    unsafe {
        ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED_P, 0) != 0
    }
}

pub fn init() -> Option<Initializer> {
    let lock = CONTROL_LOCK.lock().unwrap();
    if !is_initialized() {
        unsafe {
            if cfg!(unix) {
                ffi::gcry_control(ffi::GCRYCTL_SET_THREAD_CBS, &ffi::gcry_threads_pthread);
            }
            ffi::gcry_check_version(ptr::null());
        }
        Some(Initializer { _lock: lock })
    } else {
        None
    }
}

pub fn version() -> Option<&'static str> {
    let _lock = CONTROL_LOCK.lock().unwrap();
    if is_initialized() {
        unsafe {
            Some(utils::from_cstr(ffi::gcry_check_version(ptr::null())).unwrap())
        }
    } else {
        None
    }
}

pub unsafe trait Wrapper {
    type Raw: Copy;

    unsafe fn from_raw(raw: Self::Raw) -> Self;
    fn as_raw(&self) -> Self::Raw;
    fn into_raw(self) -> Self::Raw where Self: Sized {
        let raw = self.as_raw();
        mem::forget(self);
        raw
    }
}
