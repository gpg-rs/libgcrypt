//! ## Initialization
//! The library **must** be initialized using [```gcrypt::init```](fn.init.html) or
//! [```gcrypt::init_fips_mode```](fn.init_fips_mode.html) before
//! using any other function in the library or wrapper. More information on initialization
//! can be found in the libgcrypt
//! [documentation](https://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library).
//!
//! An example:
//!
//! ```rust
//! let token = gcrypt::init(|mut x| {
//!     x.disable_secmem();
//! });
//! ```
//!
//! The token returned by ```init``` is used as an argument to various functions in the library
//! to ensure that initialization has been completed.
extern crate libc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
#[macro_use]
pub extern crate gpg_error as error;
extern crate libgcrypt_sys as ffi;

use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;
use std::sync::Mutex;

use libc::c_int;

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
pub mod kdf;

lazy_static! {
    static ref CONTROL_LOCK: Mutex<()> = Mutex::new(());
}

pub struct Initializer(());

impl Initializer {
    pub fn check_version<S: Into<String>>(&mut self, version: S) -> bool {
        let version = match CString::new(version.into()) {
            Ok(v) => v,
            Err(..) => return false,
        };
        unsafe { !ffi::gcry_check_version(version.as_ptr()).is_null() }
    }

    pub fn enable_quick_random(&mut self) -> &mut Self {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_ENABLE_QUICK_RANDOM, 0);
        }
        self
    }

    pub fn enable_secure_rndpool(&mut self) -> &mut Self {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_USE_SECURE_RNDPOOL, 0);
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
            return_err!(ffi::gcry_control(ffi::GCRYCTL_INIT_SECMEM, amt as c_int));
        }
        Ok(self)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Token(());

impl Token {
    pub fn is_fips_mode_active(&self) -> bool {
        unsafe { ffi::gcry_control(ffi::GCRYCTL_FIPS_MODE_P, 0) != 0 }
    }

    pub fn check_version<S: Into<String>>(&self, version: S) -> bool {
        let version = match CString::new(version.into()) {
            Ok(v) => v,
            Err(..) => return false,
        };
        unsafe { !ffi::gcry_check_version(version.as_ptr()).is_null() }
    }

    pub fn version(&self) -> &'static str {
        unsafe {
            CStr::from_ptr(ffi::gcry_check_version(ptr::null()))
                .to_str()
                .expect("Version is invalid")
        }
    }

    pub fn run_self_tests(&self) -> bool {
        unsafe { ffi::gcry_control(ffi::GCRYCTL_SELFTEST, 0) == 0 }
    }

    pub fn destroy_secmem(&self) {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_TERM_SECMEM, 0);
        }
    }
}

pub fn enable_memory_guard() -> bool {
    let _lock = CONTROL_LOCK.lock().unwrap();
    let initialized = unsafe { ffi::gcry_control(ffi::GCRYCTL_ANY_INITIALIZATION_P, 0) != 0 };
    if !initialized {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_ENABLE_M_GUARD, 0);
        }
    }
    !initialized
}

pub fn is_initialized() -> bool {
    unsafe { ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED_P, 0) != 0 }
}

pub fn init<F: FnOnce(Initializer)>(f: F) -> Token {
    let _lock = CONTROL_LOCK.lock().unwrap();
    if !is_initialized() {
        unsafe {
            if cfg!(unix) {
                ffi::gcry_control(ffi::GCRYCTL_SET_THREAD_CBS,
                                  ffi::gcry_threads_pthread_shim());
            }
            ffi::gcry_check_version(ptr::null());
        }
        f(Initializer(()));
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED, 0);
        }
    }
    Token(())
}

pub fn init_fips_mode<F: FnOnce(Initializer)>(f: F) -> Token {
    let _lock = CONTROL_LOCK.lock().unwrap();
    if !is_initialized() {
        unsafe {
            if cfg!(unix) {
                ffi::gcry_control(ffi::GCRYCTL_SET_THREAD_CBS,
                                  ffi::gcry_threads_pthread_shim());
            }
            ffi::gcry_control(ffi::GCRYCTL_FORCE_FIPS_MODE, 0);
            ffi::gcry_check_version(ptr::null());
        }
        f(Initializer(()));
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED, 0);
        }
    }
    Token(())
}

pub fn get_token() -> Option<Token> {
    let _lock = CONTROL_LOCK.lock().unwrap();
    if is_initialized() {
        Some(Token(()))
    } else {
        None
    }
}

pub unsafe trait Wrapper: Sized {
    type Raw: Copy;

    unsafe fn from_raw(raw: Self::Raw) -> Self;

    fn as_raw(&self) -> Self::Raw;

    fn into_raw(self) -> Self::Raw {
        let raw = self.as_raw();
        mem::forget(self);
        raw
    }
}
