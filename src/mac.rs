use std::ffi::CString;
use std::mem;
use std::ptr;

use libc;
use ffi;

use Token;
use utils;
use error::Result;

pub const HMAC_SHA256: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_SHA256 as libc::c_int);
pub const HMAC_SHA224: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_SHA224 as libc::c_int);
pub const HMAC_SHA512: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_SHA512 as libc::c_int);
pub const HMAC_SHA384: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_SHA384 as libc::c_int);
pub const HMAC_SHA1: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_SHA1 as libc::c_int);
pub const HMAC_MD5: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_MD5 as libc::c_int);
pub const HMAC_MD4: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_MD4 as libc::c_int);
pub const HMAC_RMD160: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_RMD160 as libc::c_int);
pub const HMAC_TIGER1: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_TIGER1 as libc::c_int);
pub const HMAC_WHIRLPOOL: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_WHIRLPOOL as libc::c_int);
pub const HMAC_GOSTR3411_94: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_GOSTR3411_94 as libc::c_int);
pub const HMAC_STRIBOG256: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_STRIBOG256 as libc::c_int);
pub const HMAC_STRIBOG512: Algorithm = Algorithm(ffi::GCRY_MAC_HMAC_STRIBOG512 as libc::c_int);
pub const CMAC_AES: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_AES as libc::c_int);
pub const CMAC_3DES: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_3DES as libc::c_int);
pub const CMAC_CAMELLIA: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_CAMELLIA as libc::c_int);
pub const CMAC_CAST5: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_CAST5 as libc::c_int);
pub const CMAC_BLOWFISH: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_BLOWFISH as libc::c_int);
pub const CMAC_TWOFISH: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_TWOFISH as libc::c_int);
pub const CMAC_SERPENT: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_SERPENT as libc::c_int);
pub const CMAC_SEED: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_SEED as libc::c_int);
pub const CMAC_RFC2268: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_RFC2268 as libc::c_int);
pub const CMAC_IDEA: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_IDEA as libc::c_int);
pub const CMAC_GOST28147: Algorithm = Algorithm(ffi::GCRY_MAC_CMAC_GOST28147 as libc::c_int);
pub const GMAC_AES: Algorithm = Algorithm(ffi::GCRY_MAC_GMAC_AES as libc::c_int);
pub const GMAC_CAMELLIA: Algorithm = Algorithm(ffi::GCRY_MAC_GMAC_CAMELLIA as libc::c_int);
pub const GMAC_TWOFISH: Algorithm = Algorithm(ffi::GCRY_MAC_GMAC_TWOFISH as libc::c_int);
pub const GMAC_SERPENT: Algorithm = Algorithm(ffi::GCRY_MAC_GMAC_SERPENT as libc::c_int);
pub const GMAC_SEED: Algorithm = Algorithm(ffi::GCRY_MAC_GMAC_SEED as libc::c_int);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Algorithm(libc::c_int);

impl Algorithm {
    pub fn from_raw(raw: ffi::gcry_mac_algos) -> Algorithm {
        Algorithm(raw as libc::c_int)
    }

    pub fn as_raw(&self) -> ffi::gcry_mac_algos {
        self.0 as ffi::gcry_mac_algos
    }

    pub fn from_name<S: Into<String>>(name: S) -> Option<Algorithm> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe {
            ffi::gcry_mac_map_name(name.as_ptr())
        };
        if result != 0 {
            Some(Algorithm(result))
        } else {
            None
        }
    }

    pub fn is_available(&self) -> bool {
        unsafe {
            ffi::gcry_mac_algo_info(self.0, ffi::GCRYCTL_TEST_ALGO as libc::c_int,
                                   ptr::null_mut(), ptr::null_mut()) == 0
        }
    }

    pub fn name(&self) -> &'static str {
        unsafe {
            utils::from_cstr(ffi::gcry_mac_algo_name(self.0)).unwrap()
        }
    }

    pub fn key_len(&self) -> usize {
        unsafe {
            ffi::gcry_mac_get_algo_keylen(self.0) as usize
        }
    }

    pub fn mac_len(&self) -> usize {
        unsafe {
            ffi::gcry_mac_get_algo_maclen(self.0) as usize
        }
    }
}

bitflags! {
    flags Flags: ffi::gcry_mac_flags {
        const FLAG_SECURE = ffi::GCRY_MAC_FLAG_SECURE,
    }
}

#[derive(Debug)]
pub struct Mac {
    raw: ffi::gcry_mac_hd_t,
}

impl Drop for Mac {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_mac_close(self.raw);
        }
    }
}

impl Mac {
    pub unsafe fn from_raw(raw: ffi::gcry_mac_hd_t) -> Mac {
        Mac { raw: raw }
    }

    pub fn as_raw(&self) -> ffi::gcry_mac_hd_t {
        self.raw
    }

    pub fn new(_: Token, algo: Algorithm, flags: Flags) -> Result<Mac> {
        let mut handle: ffi::gcry_mac_hd_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_mac_open(&mut handle, algo.0, flags.bits(), ptr::null_mut()));
        }
        Ok(Mac { raw: handle })
    }

    pub fn set_key<B: AsRef<[u8]>>(&mut self, key: &B) -> Result<()> {
        let key = key.as_ref();
        unsafe {
            return_err!(ffi::gcry_mac_setkey(self.raw, mem::transmute(key.as_ptr()),
                                            key.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn set_iv<B: AsRef<[u8]>>(&mut self, iv: &B) -> Result<()> {
        let iv = iv.as_ref();
        unsafe {
            return_err!(ffi::gcry_mac_setiv(self.raw, mem::transmute(iv.as_ptr()),
                                            iv.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_mac_ctl(self.raw, ffi::GCRYCTL_RESET as libc::c_int,
                                          ptr::null_mut(), 0));
        }
        Ok(())
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_mac_write(self.raw, mem::transmute(bytes.as_ptr()),
                               bytes.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut len = buf.len() as libc::size_t;
        unsafe {
            return_err!(ffi::gcry_mac_read(self.raw, mem::transmute(buf.as_mut_ptr()),
                                           &mut len));
        }
        Ok(len as usize)
    }

    pub fn verify(&mut self, buf: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_mac_verify(self.raw, mem::transmute(buf.as_ptr()),
                                             buf.len() as libc::size_t));
        }
        Ok(())
    }
}
