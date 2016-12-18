//! ## Initialization
//! Libgcrypt requires initialization before first use. The functions `init` and `init_fips` can be
//! used to initialize the library. The closure passed to these functions is used to configure the
//! library. More information on configuration options can be found in the libgcrypt
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
//! Calling any function in the wrapper that requires initialization before `init` or `init_fips`
//! are called will cause the wrapper to attempt to initialize the library with a default
//! configuration.
#![cfg_attr(any(nightly, feature = "nightly"), feature(nonzero))]
#[macro_use]
extern crate cfg_if;
extern crate libc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate lazy_static;
#[macro_use]
pub extern crate gpg_error as error;
extern crate libgcrypt_sys as ffi;

use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{ATOMIC_BOOL_INIT, AtomicBool, Ordering};

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

cfg_if! {
    if #[cfg(feature = "v1_7_0")] {
        const TARGET_VERSION: &'static str = "1.7.0\0";
    } else if #[cfg(feature = "v1_6_0")] {
        const TARGET_VERSION: &'static str = "1.6.0\0";
    } else {
        const TARGET_VERSION: &'static str = "1.5.0\0";
    }
}

static INITIALIZED: AtomicBool = ATOMIC_BOOL_INIT;
lazy_static! {
    static ref CONTROL_LOCK: Mutex<()> = Mutex::new(());
}

pub struct Initializer(());

impl Initializer {
    #[inline]
    pub fn check_version<S: Into<String>>(&mut self, version: S) -> bool {
        let version = match CString::new(version.into()) {
            Ok(v) => v,
            Err(..) => return false,
        };
        unsafe { !ffi::gcry_check_version(version.as_ptr()).is_null() }
    }

    #[inline]
    pub fn enable_quick_random(&mut self) -> &mut Self {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_ENABLE_QUICK_RANDOM, 0);
        }
        self
    }

    #[inline]
    pub fn enable_secure_rndpool(&mut self) -> &mut Self {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_USE_SECURE_RNDPOOL, 0);
        }
        self
    }

    #[inline]
    pub fn disable_secmem(&mut self) -> &mut Self {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_DISABLE_SECMEM, 0);
        }
        self
    }

    #[inline]
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
    #[inline]
    pub fn is_fips_mode_active(&self) -> bool {
        unsafe { ffi::gcry_fips_mode_active() }
    }

    #[inline]
    pub fn check_version<S: Into<String>>(&self, version: S) -> bool {
        let version = match CString::new(version.into()) {
            Ok(v) => v,
            Err(..) => return false,
        };
        unsafe { !ffi::gcry_check_version(version.as_ptr()).is_null() }
    }

    #[inline]
    pub fn version(&self) -> &'static str {
        unsafe {
            CStr::from_ptr(ffi::gcry_check_version(ptr::null()))
                .to_str()
                .expect("Version is invalid")
        }
    }

    #[inline]
    pub fn run_self_tests(&self) -> bool {
        unsafe { ffi::gcry_control(ffi::GCRYCTL_SELFTEST, 0) == 0 }
    }

    #[inline]
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

#[inline]
fn is_init_finished() -> bool {
    unsafe { ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED_P, 0) != 0 }
}

#[inline]
pub fn is_initialized() -> bool {
    if INITIALIZED.load(Ordering::Acquire) {
        return true;
    }

    let _lock = CONTROL_LOCK.lock().unwrap();
    is_init_finished()
}

pub fn init<F: FnOnce(&mut Initializer)>(f: F) -> Token {
    if INITIALIZED.load(Ordering::Acquire) {
        return Token(());
    }

    let _lock = CONTROL_LOCK.lock().unwrap();
    if !is_init_finished() {
        unsafe {
            if cfg!(unix) {
                ffi::gcry_control(ffi::GCRYCTL_SET_THREAD_CBS,
                                  ffi::gcry_threads_pthread_shim());
            }
            assert!(!ffi::gcry_check_version(TARGET_VERSION.as_ptr() as *const _).is_null());
        }
        f(&mut Initializer(()));
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED, 0);
        }
    }
    INITIALIZED.store(true, Ordering::Release);
    Token(())
}

pub fn init_fips_mode<F: FnOnce(&mut Initializer)>(f: F) -> Token {
    if INITIALIZED.load(Ordering::Acquire) {
        return Token(());
    }

    let _lock = CONTROL_LOCK.lock().unwrap();
    if !is_init_finished() {
        unsafe {
            if cfg!(unix) {
                ffi::gcry_control(ffi::GCRYCTL_SET_THREAD_CBS,
                                  ffi::gcry_threads_pthread_shim());
            }
            ffi::gcry_control(ffi::GCRYCTL_FORCE_FIPS_MODE, 0);
            assert!(!ffi::gcry_check_version(TARGET_VERSION.as_ptr() as *const _).is_null());
        }
        f(&mut Initializer(()));
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED, 0);
        }
    }
    INITIALIZED.store(true, Ordering::Release);
    Token(())
}

#[inline]
pub fn get_token() -> Token {
    init(|mut x| { x.disable_secmem(); })
}

type NonZero<T> = utils::NonZero<T>;
