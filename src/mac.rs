use std::ffi::CString;
use std::ptr;

use libc;
use ffi;

use Wrapper;
use utils;
use error::Result;

enum_wrapper! {
    pub enum Algorithm: libc::c_int {
        HMAC_SHA256 = ffi::GCRY_MAC_HMAC_SHA256,
        HMAC_SHA224 = ffi::GCRY_MAC_HMAC_SHA224,
        HMAC_SHA512 = ffi::GCRY_MAC_HMAC_SHA512,
        HMAC_SHA384 = ffi::GCRY_MAC_HMAC_SHA384,
        HMAC_SHA1 = ffi::GCRY_MAC_HMAC_SHA1,
        HMAC_MD5 = ffi::GCRY_MAC_HMAC_MD5,
        HMAC_MD4 = ffi::GCRY_MAC_HMAC_MD4,
        HMAC_RMD160 = ffi::GCRY_MAC_HMAC_RMD160,
        HMAC_TIGER1 = ffi::GCRY_MAC_HMAC_TIGER1,
        HMAC_WHIRLPOOL = ffi::GCRY_MAC_HMAC_WHIRLPOOL,
        HMAC_GOSTR3411_94 = ffi::GCRY_MAC_HMAC_GOSTR3411_94,
        HMAC_STRIBOG256 = ffi::GCRY_MAC_HMAC_STRIBOG256,
        HMAC_STRIBOG512 = ffi::GCRY_MAC_HMAC_STRIBOG512,
        CMAC_AES = ffi::GCRY_MAC_CMAC_AES,
        CMAC_3DES = ffi::GCRY_MAC_CMAC_3DES,
        CMAC_CAMELLIA = ffi::GCRY_MAC_CMAC_CAMELLIA,
        CMAC_CAST5 = ffi::GCRY_MAC_CMAC_CAST5,
        CMAC_BLOWFISH = ffi::GCRY_MAC_CMAC_BLOWFISH,
        CMAC_TWOFISH = ffi::GCRY_MAC_CMAC_TWOFISH,
        CMAC_SERPENT = ffi::GCRY_MAC_CMAC_SERPENT,
        CMAC_SEED = ffi::GCRY_MAC_CMAC_SEED,
        CMAC_RFC2268 = ffi::GCRY_MAC_CMAC_RFC2268,
        CMAC_IDEA = ffi::GCRY_MAC_CMAC_IDEA,
        CMAC_GOST28147 = ffi::GCRY_MAC_CMAC_GOST28147,
        GMAC_AES = ffi::GCRY_MAC_GMAC_AES,
        GMAC_CAMELLIA = ffi::GCRY_MAC_GMAC_CAMELLIA,
        GMAC_TWOFISH = ffi::GCRY_MAC_GMAC_TWOFISH,
        GMAC_SERPENT = ffi::GCRY_MAC_GMAC_SERPENT,
        GMAC_SEED = ffi::GCRY_MAC_GMAC_SEED,
    }
}

impl Algorithm {
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

unsafe impl Wrapper for Mac {
    type Raw = ffi::gcry_mac_hd_t;

    unsafe fn from_raw(raw: ffi::gcry_mac_hd_t) -> Mac {
        debug_assert!(!raw.is_null());
        Mac { raw: raw }
    }

    fn as_raw(&self) -> ffi::gcry_mac_hd_t {
        self.raw
    }
}

impl Mac {
    pub fn new(algo: Algorithm, flags: Flags) -> Result<Mac> {
        let mut handle: ffi::gcry_mac_hd_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_mac_open(&mut handle, algo.0, flags.bits(), ptr::null_mut()));
        }
        Ok(Mac { raw: handle })
    }

    pub fn set_key<B: AsRef<[u8]>>(&mut self, key: &B) -> Result<()> {
        let key = key.as_ref();
        unsafe {
            return_err!(ffi::gcry_mac_setkey(self.raw, key.as_ptr() as *const _,
                                            key.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn set_iv<B: AsRef<[u8]>>(&mut self, iv: &B) -> Result<()> {
        let iv = iv.as_ref();
        unsafe {
            return_err!(ffi::gcry_mac_setiv(self.raw, iv.as_ptr() as *const _,
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
            return_err!(ffi::gcry_mac_write(self.raw, bytes.as_ptr() as *const _,
                               bytes.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut len = buf.len() as libc::size_t;
        unsafe {
            return_err!(ffi::gcry_mac_read(self.raw, buf.as_mut_ptr() as *mut _,
                                           &mut len));
        }
        Ok(len as usize)
    }

    pub fn verify(&mut self, buf: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_mac_verify(self.raw, buf.as_ptr() as *mut _,
                                             buf.len() as libc::size_t));
        }
        Ok(())
    }
}
