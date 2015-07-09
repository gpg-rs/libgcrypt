use std::ffi::CString;
use std::ptr;
use std::slice;

use libc;
use ffi;

use {Wrapper, Token};
use utils;
use error::Result;

enum_wrapper! {
    pub enum Algorithm: libc::c_int {
        MD_NONE = ffi::GCRY_MD_NONE,
        MD_MD5 = ffi::GCRY_MD_MD5,
        MD_SHA1 = ffi::GCRY_MD_SHA1,
        MD_RMD160 = ffi::GCRY_MD_RMD160,
        MD_MD2 = ffi::GCRY_MD_MD2,
        MD_TIGER = ffi::GCRY_MD_TIGER,
        MD_HAVAL = ffi::GCRY_MD_HAVAL,
        MD_SHA256 = ffi::GCRY_MD_SHA256,
        MD_SHA384 = ffi::GCRY_MD_SHA384,
        MD_SHA512 = ffi::GCRY_MD_SHA512,
        MD_SHA224 = ffi::GCRY_MD_SHA224,
        MD_MD4 = ffi::GCRY_MD_MD4,
        MD_CRC32 = ffi::GCRY_MD_CRC32,
        MD_CRC32_RFC1510 = ffi::GCRY_MD_CRC32_RFC1510,
        MD_CRC24_RFC2440 = ffi::GCRY_MD_CRC24_RFC2440,
        MD_WHIRLPOOL = ffi::GCRY_MD_WHIRLPOOL,
        MD_TIGER1 = ffi::GCRY_MD_TIGER1,
        MD_TIGER2 = ffi::GCRY_MD_TIGER2,
        MD_GOSTR3411_94 = ffi::GCRY_MD_GOSTR3411_94,
        MD_STRIBOG256 = ffi::GCRY_MD_STRIBOG256,
        MD_STRIBOG512 = ffi::GCRY_MD_STRIBOG512,
    }
}

impl Algorithm {
    pub fn from_name<S: Into<String>>(name: S) -> Option<Algorithm> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe {
            ffi::gcry_md_map_name(name.as_ptr())
        };
        if result != 0 {
            Some(Algorithm(result))
        } else {
            None
        }
    }

    pub fn is_available(&self, _: Token) -> bool {
        unsafe {
            ffi::gcry_md_algo_info(self.0, ffi::GCRYCTL_TEST_ALGO as libc::c_int,
                                   ptr::null_mut(), ptr::null_mut()) == 0
        }
    }

    pub fn name(&self) -> &'static str {
        unsafe {
            utils::from_cstr(ffi::gcry_md_algo_name(self.0)).unwrap()
        }
    }

    pub fn digest_len(&self) -> usize {
        unsafe {
            ffi::gcry_md_get_algo_dlen(self.0) as usize
        }
    }
}

bitflags! {
    flags Flags: ffi::gcry_md_flags {
        const FLAG_SECURE = ffi::GCRY_MD_FLAG_SECURE,
        const FLAG_HMAC = ffi::GCRY_MD_FLAG_HMAC,
        const FLAG_BUGEMU1 = ffi::GCRY_MD_FLAG_BUGEMU1,
    }
}

#[derive(Debug)]
pub struct MessageDigest {
    raw: ffi::gcry_md_hd_t,
}

impl Drop for MessageDigest {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_md_close(self.raw);
        }
    }
}

unsafe impl Wrapper for MessageDigest {
    type Raw = ffi::gcry_md_hd_t;

    unsafe fn from_raw(raw: ffi::gcry_md_hd_t) -> MessageDigest {
        debug_assert!(!raw.is_null());
        MessageDigest { raw: raw }
    }

    fn as_raw(&self) -> ffi::gcry_md_hd_t {
        self.raw
    }
}

impl MessageDigest {
    pub fn new(_: Token, algo: Algorithm, flags: Flags) -> Result<MessageDigest> {
        let mut handle: ffi::gcry_md_hd_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_md_open(&mut handle, algo.0, flags.bits()));
        }
        Ok(MessageDigest { raw: handle })
    }

    pub fn try_clone(&self) -> Result<MessageDigest> {
        let mut handle: ffi::gcry_md_hd_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_md_copy(&mut handle, self.raw));
        }
        Ok(MessageDigest { raw: handle })
    }

    pub fn enable(&mut self, algo: Algorithm) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_md_enable(self.raw, algo.0));
        }
        Ok(())
    }

    pub fn is_enabled(&self, algo: Algorithm) -> bool {
        unsafe {
            ffi::gcry_md_is_enabled(self.raw, algo.0) != 0
        }
    }

    pub fn is_secure(&self) -> bool {
        unsafe {
            ffi::gcry_md_is_secure(self.raw) != 0
        }
    }

    pub fn set_key(&mut self, key: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_md_setkey(self.raw, key.as_ptr() as *const _,
                                            key.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        unsafe {
            ffi::gcry_md_reset(self.raw)
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::gcry_md_write(self.raw, bytes.as_ptr() as *const _,
                               bytes.len() as libc::size_t);
        }
    }

    pub fn finish(&mut self) {
        unsafe {
            ffi::gcry_md_ctl(self.raw, ffi::GCRYCTL_FINALIZE as libc::c_int, ptr::null_mut(), 0);
        }
    }

    pub fn get_only_digest(&mut self) -> Option<&[u8]> {
        let algo = unsafe {
            ffi::gcry_md_get_algo(self.raw)
        };
        if algo != 0 {
            self.get_digest(Algorithm(algo))
        } else {
            None
        }
    }

    pub fn get_digest(&mut self, algo: Algorithm) -> Option<&[u8]> {
        if algo.digest_len() == 0 {
            return None;
        }

        unsafe {
            let result = ffi::gcry_md_read(self.raw, algo.0);
            if !result.is_null() {
                Some(slice::from_raw_parts(result, algo.digest_len()))
            } else {
                None
            }
        }
    }
}
