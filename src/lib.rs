//! ## Initialization
//! Libgcrypt requires initialization before first use. The functions `init` and `init_fips` can be
//! used to initialize the library. The closure passed to these functions is used to configure the
//! library. More information on configuration options can be found in the libgcrypt
//! [documentation](https://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library).
//!
//! An example:
//!
//! ```rust
//! let gcrypt = gcrypt::init::<(), _>(|x| {
//!     x.disable_secmem();
//!     Ok(())
//! });
//! ```
//!
//! Calling any function in the wrapper that requires initialization before `init` or `init_fips`
//! are called will cause the wrapper to attempt to initialize the library with a default
//! configuration.
#![deny(missing_debug_implementations)]
#![cfg_attr(any(nightly, feature = "nightly"), feature(allocator_api))]
#[macro_use]
extern crate bitflags;
extern crate cstr_argument;
#[macro_use]
pub extern crate gpg_error as error;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate libgcrypt_sys as ffi;

use std::ffi::CStr;
use std::ptr;
use std::result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use cstr_argument::CStrArgument;
use libc::c_int;

pub use buffer::Buffer;
pub use error::{Error, Result};

#[macro_use]
mod utils;
#[cfg(any(nightly, feature = "nightly"))]
pub mod alloc;
pub mod buffer;
pub mod cipher;
pub mod digest;
pub mod kdf;
pub mod mac;
pub mod mpi;
pub mod pkey;
pub mod rand;
pub mod sexp;

type NonNull<T> = ptr::NonNull<<T as utils::Ptr>::Inner>;

static INITIALIZED: AtomicBool = AtomicBool::new(false);
lazy_static! {
    static ref CONTROL_LOCK: Mutex<()> = Mutex::new(());
}

#[derive(Debug)]
pub struct Initializer(());

impl Initializer {
    #[inline]
    pub fn check_version<S: CStrArgument>(&mut self, version: S) -> bool {
        let version = version.into_cstr();
        unsafe { !ffi::gcry_check_version(version.as_ref().as_ptr()).is_null() }
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

    #[inline]
    pub fn run_self_tests(&mut self) -> Result<&mut Self> {
        unsafe {
            return_err!(ffi::gcry_control(ffi::GCRYCTL_SELFTEST, 0));
        }
        Ok(self)
    }
}

#[inline]
fn is_init_started() -> bool {
    unsafe { ffi::gcry_control(ffi::GCRYCTL_ANY_INITIALIZATION_P, 0) != 0 }
}

#[inline]
fn is_init_finished() -> bool {
    unsafe { ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED_P, 0) != 0 }
}

pub fn enable_memory_guard() -> bool {
    let _lock = CONTROL_LOCK.lock().unwrap();
    let started = is_init_started();
    if !started {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_ENABLE_M_GUARD, 0);
        }
    }
    !started
}

#[inline]
pub fn is_initialized() -> bool {
    if INITIALIZED.load(Ordering::Acquire) {
        return true;
    }
    let _lock = CONTROL_LOCK.lock();
    is_init_finished()
}

fn init_internal<E, F>(fips: bool, f: F) -> result::Result<Gcrypt, E>
where F: FnOnce(&mut Initializer) -> result::Result<(), E> {
    if INITIALIZED.load(Ordering::Acquire) {
        return Ok(Gcrypt(()));
    }

    let _lock = CONTROL_LOCK.lock();
    if !is_init_finished() {
        unsafe {
            if is_init_started() {
                if cfg!(unix) {
                    ffi::gcry_control(
                        ffi::GCRYCTL_SET_THREAD_CBS,
                        ffi::gcry_threads_pthread_shim(),
                    );
                }
                if fips {
                    ffi::gcry_control(ffi::GCRYCTL_FORCE_FIPS_MODE, 0);
                }
                assert!(!ffi::gcry_check_version(ptr::null()).is_null());
            }
        }
        f(&mut Initializer(()))?;
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_INITIALIZATION_FINISHED, 0);
        }
    }
    INITIALIZED.store(true, Ordering::Release);
    Ok(Gcrypt(()))
}

#[inline]
pub fn init<E, F>(f: F) -> result::Result<Gcrypt, E>
where F: FnOnce(&mut Initializer) -> result::Result<(), E> {
    init_internal(false, f)
}

#[inline]
pub fn init_fips_mode<E, F>(f: F) -> result::Result<Gcrypt, E>
where F: FnOnce(&mut Initializer) -> result::Result<(), E> {
    init_internal(true, f)
}

#[inline]
pub fn init_default() -> Gcrypt {
    let _ = init::<(), _>(|x| {
        x.enable_secure_rndpool().disable_secmem();
        Ok(())
    });
    Gcrypt(())
}

#[derive(Debug, Copy, Clone)]
pub struct Gcrypt(());

impl Gcrypt {
    #[inline]
    pub fn is_fips_mode_active(&self) -> bool {
        unsafe { ffi::gcry_fips_mode_active() }
    }

    #[inline]
    pub fn check_version<S: CStrArgument>(&self, version: S) -> bool {
        let version = version.into_cstr();
        unsafe { !ffi::gcry_check_version(version.as_ref().as_ptr()).is_null() }
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
    pub fn run_self_tests(&self) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_control(ffi::GCRYCTL_SELFTEST, 0));
        }
        Ok(())
    }

    #[inline]
    pub fn destroy_secmem(&self) {
        unsafe {
            ffi::gcry_control(ffi::GCRYCTL_TERM_SECMEM, 0);
        }
    }
}
