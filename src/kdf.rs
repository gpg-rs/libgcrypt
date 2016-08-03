use std::ptr;

use ffi;
use libc::c_int;

use Token;
use error::Result;
use digest::Algorithm as DigestAlgorithm;

enum_wrapper! {
    pub enum Algorithm: c_int {
        KDF_SIMPLE_S2K = ffi::GCRY_KDF_SIMPLE_S2K,
        KDF_SALTED_S2K = ffi::GCRY_KDF_SALTED_S2K,
        KDF_ITERSALTED_S2K = ffi::GCRY_KDF_ITERSALTED_S2K,
        KDF_PBKDF1 = ffi::GCRY_KDF_PBKDF1,
        KDF_PBKDF2 = ffi::GCRY_KDF_PBKDF2,
        KDF_SCRYPT = ffi::GCRY_KDF_SCRYPT,
    }
}

pub fn derive(_: Token, algo: Algorithm, subalgo: i16, iter: u32, pass: &[u8],
              salt: Option<&[u8]>, key: &mut [u8])
              -> Result<()> {
    unsafe {
        let salt = salt.map_or((ptr::null(), 0), |s| (s.as_ptr(), s.len()));
        return_err!(ffi::gcry_kdf_derive(pass.as_ptr() as *const _,
                                         pass.len(), algo.raw(),
                                         subalgo.into(),
                                         salt.0 as *const _, salt.1,
                                         iter.into(),
                                         key.len(), key.as_mut_ptr() as *mut _));
    }
    Ok(())
}

pub fn s2k_derive(token: Token, algo: DigestAlgorithm, iter: u32,
                  pass: &[u8], salt: Option<&[u8]>, key: &mut [u8]) -> Result<()> {
    match (iter, salt.is_some()) {
        (x, true) if x != 0 => {
            derive(token, KDF_ITERSALTED_S2K, algo.raw() as i16, iter, pass, salt, key)
        }
        (_, true) => {
            derive(token, KDF_SALTED_S2K, algo.raw() as i16, iter, pass, salt, key)
        }
        _ => {
            derive(token, KDF_SIMPLE_S2K, algo.raw() as i16, iter, pass, salt, key)
        }
    }
}

pub fn pbkdf1_derive(token: Token, algo: DigestAlgorithm, iter: u32,
                     pass: &[u8], salt: &[u8], key: &mut [u8]) -> Result<()> {
    derive(token, KDF_PBKDF1, algo.raw() as i16, iter, pass, Some(salt), key)
}

pub fn pbkdf2_derive(token: Token, algo: DigestAlgorithm, iter: u32,
                     pass: &[u8], salt: &[u8], key: &mut [u8]) -> Result<()> {
    derive(token, KDF_PBKDF2, algo.raw() as i16, iter, pass, Some(salt), key)
}

pub fn scrypt_derive(_: Token, n: u32, p: u32,
                     pass: &[u8], salt: &[u8], key: &mut [u8]) -> Result<()> {
    unsafe {
        return_err!(ffi::gcry_kdf_derive(pass.as_ptr() as *const _,
                                         pass.len(), KDF_SCRYPT.raw(),
                                         n as c_int,
                                         salt.as_ptr() as *const _, salt.len(),
                                         p.into(),
                                         key.len(), key.as_mut_ptr() as *mut _));
    }
    Ok(())
}
