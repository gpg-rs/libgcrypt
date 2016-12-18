use std::ffi::CString;
use std::ptr;

use ffi;
use libc::c_int;

use utils;
use error::Result;
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
    pub fn from_name<S: Into<String>>(name: S) -> Option<Algorithm> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe { ffi::gcry_pk_map_name(name.as_ptr()) };
        if result != 0 {
            unsafe { Some(Algorithm::from_raw(result)) }
        } else {
            None
        }
    }

    pub fn is_available(&self) -> bool {
        let _ = ::get_token();
        unsafe { ffi::gcry_pk_test_algo(self.raw()) == 0 }
    }

    pub fn name(&self) -> Option<&'static str> {
        unsafe { utils::from_cstr(ffi::gcry_pk_algo_name(self.raw())) }
    }
}

impl SExpression {
    pub fn num_bits(&self) -> Option<usize> {
        unsafe {
            let result = ffi::gcry_pk_get_nbits(self.as_raw());
            if result != 0 {
                Some(result as usize)
            } else {
                None
            }
        }
    }

    pub fn key_grip(&self) -> Option<[u8; 20]> {
        unsafe {
            let mut buffer = [0u8; 20];
            if !ffi::gcry_pk_get_keygrip(self.as_raw(), buffer.as_mut_ptr()).is_null() {
                Some(buffer)
            } else {
                None
            }
        }
    }

    pub fn curve(&self) -> Option<Curve> {
        Curves::from(self).next()
    }

    pub fn test_key(&self) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_pk_testkey(self.as_raw()));
            Ok(())
        }
    }
}

pub fn generate_key(config: &SExpression) -> Result<SExpression> {
    unsafe {
        let mut result: ffi::gcry_sexp_t = ptr::null_mut();
        return_err!(ffi::gcry_pk_genkey(&mut result, config.as_raw()));
        Ok(SExpression::from_raw(result))
    }
}

pub fn encrypt(key: &SExpression, data: &SExpression) -> Result<SExpression> {
    unsafe {
        let mut result: ffi::gcry_sexp_t = ptr::null_mut();
        return_err!(ffi::gcry_pk_encrypt(&mut result, data.as_raw(), key.as_raw()));
        Ok(SExpression::from_raw(result))
    }
}

pub fn decrypt(key: &SExpression, data: &SExpression) -> Result<SExpression> {
    unsafe {
        let mut result: ffi::gcry_sexp_t = ptr::null_mut();
        return_err!(ffi::gcry_pk_decrypt(&mut result, data.as_raw(), key.as_raw()));
        Ok(SExpression::from_raw(result))
    }
}

pub fn sign(key: &SExpression, data: &SExpression) -> Result<SExpression> {
    unsafe {
        let mut result: ffi::gcry_sexp_t = ptr::null_mut();
        return_err!(ffi::gcry_pk_sign(&mut result, data.as_raw(), key.as_raw()));
        Ok(SExpression::from_raw(result))
    }
}

pub fn verify(key: &SExpression, data: &SExpression, sig: &SExpression) -> Result<()> {
    unsafe {
        return_err!(ffi::gcry_pk_verify(sig.as_raw(), data.as_raw(), key.as_raw()));
        Ok(())
    }
}
