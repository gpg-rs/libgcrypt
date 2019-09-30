use std::ptr;

use ffi;
use libc::c_int;

use crate::{digest::Algorithm as DigestAlgorithm, error::return_err, Result};

ffi_enum_wrapper! {
    pub enum Algorithm: c_int {
        SimpleS2K = ffi::GCRY_KDF_SIMPLE_S2K,
        SaltedS2K = ffi::GCRY_KDF_SALTED_S2K,
        IteratedSaltedS2K = ffi::GCRY_KDF_ITERSALTED_S2K,
        Pbkdf1 = ffi::GCRY_KDF_PBKDF1,
        Pbkdf2 = ffi::GCRY_KDF_PBKDF2,
        Scrypt = ffi::GCRY_KDF_SCRYPT,
    }
}

#[inline]
pub fn derive(
    algo: Algorithm, subalgo: i32, iter: u32, secret: &[u8], salt: Option<&[u8]>, key: &mut [u8],
) -> Result<()> {
    let _ = crate::init_default();
    unsafe {
        let salt = salt.map_or((ptr::null(), 0), |s| (s.as_ptr(), s.len()));
        return_err!(ffi::gcry_kdf_derive(
            secret.as_ptr().cast(),
            secret.len(),
            algo.raw(),
            subalgo as c_int,
            salt.0.cast(),
            salt.1,
            iter.into(),
            key.len(),
            key.as_mut_ptr().cast(),
        ));
    }
    Ok(())
}

#[inline]
pub fn s2k_derive(
    digest: DigestAlgorithm, iter: u32, secret: &[u8], salt: Option<&[u8]>, key: &mut [u8],
) -> Result<()> {
    let variant = match (iter, salt.is_some()) {
        (0, true) => Algorithm::SaltedS2K,
        (_, true) => Algorithm::IteratedSaltedS2K,
        _ => Algorithm::SimpleS2K,
    };
    derive(variant, digest.raw(), iter, secret, salt, key)
}

#[inline]
pub fn pbkdf1_derive(
    digest: DigestAlgorithm, iter: u32, secret: &[u8], salt: &[u8], key: &mut [u8],
) -> Result<()> {
    derive(
        Algorithm::Pbkdf1,
        digest.raw(),
        iter,
        secret,
        Some(salt),
        key,
    )
}

#[inline]
pub fn pbkdf2_derive(
    digest: DigestAlgorithm, iter: u32, secret: &[u8], salt: &[u8], key: &mut [u8],
) -> Result<()> {
    derive(
        Algorithm::Pbkdf2,
        digest.raw(),
        iter,
        secret,
        Some(salt),
        key,
    )
}

#[inline]
pub fn scrypt_derive(n: u32, p: u32, secret: &[u8], salt: &[u8], key: &mut [u8]) -> Result<()> {
    derive(Algorithm::Scrypt, n as i32, p, secret, Some(salt), key)
}
