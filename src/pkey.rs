use std::ffi::CString;
use std::ptr;

use libc;
use ffi;

use Wrapper;
use utils;
use error::Result;
use sexp::SExpression;

enum_wrapper! {
    pub enum Algorithm: libc::c_int {
        PK_RSA = ffi::GCRY_PK_RSA,
        PK_RSA_E = ffi::GCRY_PK_RSA_E,
        PK_RSA_S = ffi::GCRY_PK_RSA_S,
        PK_ELG_E = ffi::GCRY_PK_ELG_E,
        PK_DSA = ffi::GCRY_PK_DSA,
        PK_ECC = ffi::GCRY_PK_ECC,
        PK_ELG = ffi::GCRY_PK_ELG,
        PK_ECDSA = ffi::GCRY_PK_ECDSA,
        PK_ECDH = ffi::GCRY_PK_ECDH,
    }
}

impl Algorithm {
    pub fn from_name<S: Into<String>>(name: S) -> Option<Algorithm> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe {
            ffi::gcry_pk_map_name(name.as_ptr())
        };
        if result != 0 {
            Some(Algorithm(result))
        } else {
            None
        }
    }

    pub fn is_available(&self) -> bool {
        unsafe {
            ffi::gcry_pk_algo_info(self.0, ffi::GCRYCTL_TEST_ALGO as libc::c_int,
                                   ptr::null_mut(), ptr::null_mut()) == 0
        }
    }

    pub fn name(&self) -> &'static str {
        unsafe {
            utils::from_cstr(ffi::gcry_pk_algo_name(self.0)).unwrap()
        }
    }
}

impl SExpression {
    pub fn generate_key(parms: &SExpression) -> Result<SExpression> {
        unsafe {
            let mut result: ffi::gcry_sexp_t = ptr::null_mut();
            return_err!(ffi::gcry_pk_genkey(&mut result, parms.as_raw()));
            Ok(SExpression::from_raw(result))
        }
    }

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
            let mut buffer = [0 as u8; 20];
            if !ffi::gcry_pk_get_keygrip(self.as_raw(), buffer.as_mut_ptr()).is_null() {
                Some(buffer)
            } else {
                None
            }
        }
    }

    pub fn test_key(&self) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_pk_testkey(self.as_raw()));
            Ok(())
        }
    }

    pub fn encrypt(&self, data: &SExpression) -> Result<SExpression> {
        unsafe {
            let mut result: ffi::gcry_sexp_t = ptr::null_mut();
            return_err!(ffi::gcry_pk_encrypt(&mut result, data.as_raw(), self.as_raw()));
            Ok(SExpression::from_raw(result))
        }
    }

    pub fn decrypt(&self, data: &SExpression) -> Result<SExpression> {
        unsafe {
            let mut result: ffi::gcry_sexp_t = ptr::null_mut();
            return_err!(ffi::gcry_pk_decrypt(&mut result, data.as_raw(), self.as_raw()));
            Ok(SExpression::from_raw(result))
        }
    }

    pub fn sign(&self, data: &SExpression) -> Result<SExpression> {
        unsafe {
            let mut result: ffi::gcry_sexp_t = ptr::null_mut();
            return_err!(ffi::gcry_pk_sign(&mut result, data.as_raw(), self.as_raw()));
            Ok(SExpression::from_raw(result))
        }
    }

    pub fn verify(&self, sig: &SExpression, data: &SExpression) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_pk_verify(sig.as_raw(), data.as_raw(), self.as_raw()));
            Ok(())
        }
    }
}

