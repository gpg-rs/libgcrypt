use std::ptr;

use ffi;
use libc::c_int;

use digest::Algorithm as DigestAlgorithm;
use error::Result;

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
    algo: Algorithm, subalgo: i32, iter: u32, pass: &[u8], salt: Option<&[u8]>, key: &mut [u8],
) -> Result<()> {
    let _ = ::init_default();
    unsafe {
        let salt = salt.map_or((ptr::null(), 0), |s| (s.as_ptr(), s.len()));
        return_err!(ffi::gcry_kdf_derive(
            pass.as_ptr() as *const _,
            pass.len(),
            algo.raw(),
            subalgo as c_int,
            salt.0 as *const _,
            salt.1,
            iter.into(),
            key.len(),
            key.as_mut_ptr() as *mut _
        ));
    }
    Ok(())
}

#[inline]
pub fn s2k_derive(
    algo: DigestAlgorithm, iter: u32, pass: &[u8], salt: Option<&[u8]>, key: &mut [u8],
) -> Result<()> {
    match (iter, salt.is_some()) {
        (x, true) if x != 0 => derive(
            Algorithm::IteratedSaltedS2K,
            algo.raw() as i32,
            iter,
            pass,
            salt,
            key,
        ),
        (_, true) => derive(
            Algorithm::SaltedS2K,
            algo.raw() as i32,
            iter,
            pass,
            salt,
            key,
        ),
        _ => derive(
            Algorithm::SimpleS2K,
            algo.raw() as i32,
            iter,
            pass,
            salt,
            key,
        ),
    }
}

#[inline]
pub fn pbkdf1_derive(
    algo: DigestAlgorithm, iter: u32, pass: &[u8], salt: &[u8], key: &mut [u8],
) -> Result<()> {
    derive(
        Algorithm::Pbkdf1,
        algo.raw() as i32,
        iter,
        pass,
        Some(salt),
        key,
    )
}

#[inline]
pub fn pbkdf2_derive(
    algo: DigestAlgorithm, iter: u32, pass: &[u8], salt: &[u8], key: &mut [u8],
) -> Result<()> {
    derive(
        Algorithm::Pbkdf2,
        algo.raw() as i32,
        iter,
        pass,
        Some(salt),
        key,
    )
}

#[inline]
pub fn scrypt_derive(n: u32, p: u32, pass: &[u8], salt: &[u8], key: &mut [u8]) -> Result<()> {
    derive(Algorithm::Scrypt, n as i32, p, pass, Some(salt), key)
}
