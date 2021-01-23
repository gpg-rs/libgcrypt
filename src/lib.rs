//! ## Initialization
//! Libgcrypt requires initialization before first use. The functions `init` and `init_fips` can be
//! used to initialize the library. The closure passed to these functions is used to configure the
//! library. More information on configuration options can be found in the libgcrypt
//! [documentation](https://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library).
//!
//! An example:
//!
//! ```rust
//! let gcrypt = gcrypt::init(|x| {
//!     x.disable_secmem();
//!     Ok::<_, ()>(())
//! });
//! ```
//!
//! Calling any function in the wrapper that requires initialization before `init` or `init_fips`
//! are called will cause the wrapper to attempt to initialize the library with a default
//! configuration.
#![deny(missing_debug_implementations)]

use std::{
    ffi::CStr,
    ptr, result,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

use cstr_argument::CStrArgument;
use once_cell::sync::Lazy;

use self::error::return_err;

pub use crate::{
    buffer::Buffer,
    error::{Error, Result},
};

pub use ffi::{require_gcrypt_ver, MIN_GCRYPT_VERSION};
pub use gpg_error as error;

#[macro_use]
mod utils;
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
static CONTROL_LOCK: Lazy<Mutex<()>> = Lazy::new(Mutex::default);

#[derive(Debug)]
pub struct Initializer(());

impl Initializer {
    #[inline]
    pub fn check_version(&mut self, version: impl CStrArgument) -> bool {
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
            return_err!(ffi::gcry_control(
                ffi::GCRYCTL_INIT_SECMEM,
                amt as libc::c_uint
            ));
        }
        Ok(self)
    }

    #[inline]
    pub fn enable_auto_expand_secmem(&mut self, amt: usize) -> Result<&mut Self> {
        unsafe {
            return_err!(ffi::gcry_control(
                ffi::GCRYCTL_AUTO_EXPAND_SECMEM,
                amt as libc::c_uint
            ));
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

fn init_internal<E>(
    fips: bool, f: impl FnOnce(&mut Initializer) -> result::Result<(), E>,
) -> result::Result<Gcrypt, E> {
    if INITIALIZED.load(Ordering::Acquire) {
        return Ok(Gcrypt(()));
    }

    let _lock = CONTROL_LOCK.lock().unwrap();
    if !is_init_finished() {
        unsafe {
            if !is_init_started() {
                if cfg!(unix) {
                    ffi::gcry_control(
                        ffi::GCRYCTL_SET_THREAD_CBS,
                        ffi::gcry_threads_pthread_shim(),
                    );
                }
                if fips {
                    ffi::gcry_control(ffi::GCRYCTL_FORCE_FIPS_MODE, 0);
                }
            }
            assert!(
                !ffi::gcry_check_version(MIN_GCRYPT_VERSION.as_ptr().cast()).is_null(),
                "the library linked is not the correct version"
            );
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
pub fn init<E>(
    f: impl FnOnce(&mut Initializer) -> result::Result<(), E>,
) -> result::Result<Gcrypt, E> {
    init_internal(false, f)
}

#[inline]
pub fn init_fips_mode<E>(
    f: impl FnOnce(&mut Initializer) -> result::Result<(), E>,
) -> result::Result<Gcrypt, E> {
    init_internal(true, f)
}

#[inline]
pub fn init_default() -> Gcrypt {
    let _ = init(|x| {
        x.enable_secure_rndpool().disable_secmem();
        Ok::<_, ()>(())
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
    pub fn check_version(&self, version: impl CStrArgument) -> bool {
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
