use std::ffi::CStr;
use std::ptr;
use std::result;
use std::str::Utf8Error;

use ffi;
use libc::c_int;
use cstr_argument::CStrArgument;

use Result;
use sexp::SExpression;
use mpi::ec::{Curve, Curves};

ffi_enum_wrapper! {
    pub enum Algorithm: c_int {
        Rsa        = ffi::GCRY_PK_RSA,
        RsaEncrypt = ffi::GCRY_PK_RSA_E,
        RsaSign    = ffi::GCRY_PK_RSA_S,
        ElgEncrypt = ffi::GCRY_PK_ELG_E,
        Dsa        = ffi::GCRY_PK_DSA,
        Ecc        = ffi::GCRY_PK_ECC,
        Elg        = ffi::GCRY_PK_ELG,
        Ecdsa      = ffi::GCRY_PK_ECDSA,
        Ecdh       = ffi::GCRY_PK_ECDH,
        Eddsa      = ffi::GCRY_PK_EDDSA,
    }
}

impl Algorithm {
    #[inline]
    pub fn from_name<S: CStrArgument>(name: S) -> Option<Algorithm> {
        let name = name.into_cstr();
        let result = unsafe { ffi::gcry_pk_map_name(name.as_ref().as_ptr()) };
        if result != 0 {
            unsafe { Some(Algorithm::from_raw(result)) }
        } else {
            None
        }
    }

    #[inline]
    pub fn is_available(&self) -> bool {
        let _ = ::get_token();
        unsafe { ffi::gcry_pk_test_algo(self.raw()) == 0 }
    }

    #[inline]
    pub fn name(&self) -> result::Result<&'static str, Option<Utf8Error>> {
        self.name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'static CStr> {
        unsafe {
            ffi::gcry_pk_algo_name(self.raw())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }
}

#[inline]
pub fn num_bits(key: &SExpression) -> Option<usize> {
    unsafe {
        let result = ffi::gcry_pk_get_nbits(key.as_raw());
        if result != 0 {
            Some(result as usize)
        } else {
            None
        }
    }
}

#[inline]
pub fn key_grip(key: &SExpression) -> Option<[u8; 20]> {
    unsafe {
        let mut buffer = [0u8; 20];
        if !ffi::gcry_pk_get_keygrip(key.as_raw(), buffer.as_mut_ptr()).is_null() {
            Some(buffer)
        } else {
            None
        }
    }
}

#[inline]
pub fn curve(key: &SExpression) -> Option<Curve> {
    Curves::from(key).next()
}

#[inline]
pub fn test_key(key: &SExpression) -> Result<()> {
    unsafe {
        return_err!(ffi::gcry_pk_testkey(key.as_raw()));
        Ok(())
    }
}

#[inline]
pub fn generate_key(config: &SExpression) -> Result<SExpression> {
    unsafe {
        let mut result: ffi::gcry_sexp_t = ptr::null_mut();
        return_err!(ffi::gcry_pk_genkey(&mut result, config.as_raw()));
        Ok(SExpression::from_raw(result))
    }
}

#[inline]
pub fn encrypt(key: &SExpression, data: &SExpression) -> Result<SExpression> {
    unsafe {
        let mut result: ffi::gcry_sexp_t = ptr::null_mut();
        return_err!(ffi::gcry_pk_encrypt(
            &mut result,
            data.as_raw(),
            key.as_raw()
        ));
        Ok(SExpression::from_raw(result))
    }
}

#[inline]
pub fn decrypt(key: &SExpression, data: &SExpression) -> Result<SExpression> {
    unsafe {
        let mut result: ffi::gcry_sexp_t = ptr::null_mut();
        return_err!(ffi::gcry_pk_decrypt(
            &mut result,
            data.as_raw(),
            key.as_raw()
        ));
        Ok(SExpression::from_raw(result))
    }
}

#[inline]
pub fn sign(key: &SExpression, data: &SExpression) -> Result<SExpression> {
    unsafe {
        let mut result: ffi::gcry_sexp_t = ptr::null_mut();
        return_err!(ffi::gcry_pk_sign(&mut result, data.as_raw(), key.as_raw()));
        Ok(SExpression::from_raw(result))
    }
}

#[inline]
pub fn verify(key: &SExpression, data: &SExpression, sig: &SExpression) -> Result<()> {
    unsafe {
        return_err!(ffi::gcry_pk_verify(
            sig.as_raw(),
            data.as_raw(),
            key.as_raw()
        ));
        Ok(())
    }
}
