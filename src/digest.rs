use std::ffi::CString;
use std::mem;
use std::ptr;
use std::slice;

use libc;
use ffi;

use Token;
use utils;
use error::Result;

pub const MD_NONE: Algorithm = Algorithm(ffi::GCRY_MD_NONE as libc::c_int);
pub const MD_MD5: Algorithm = Algorithm(ffi::GCRY_MD_MD5 as libc::c_int);
pub const MD_SHA1: Algorithm = Algorithm(ffi::GCRY_MD_SHA1 as libc::c_int);
pub const MD_RMD160: Algorithm = Algorithm(ffi::GCRY_MD_RMD160 as libc::c_int);
pub const MD_MD2: Algorithm = Algorithm(ffi::GCRY_MD_MD2 as libc::c_int);
pub const MD_TIGER: Algorithm = Algorithm(ffi::GCRY_MD_TIGER as libc::c_int);
pub const MD_HAVAL: Algorithm = Algorithm(ffi::GCRY_MD_HAVAL as libc::c_int);
pub const MD_SHA256: Algorithm = Algorithm(ffi::GCRY_MD_SHA256 as libc::c_int);
pub const MD_SHA384: Algorithm = Algorithm(ffi::GCRY_MD_SHA384 as libc::c_int);
pub const MD_SHA512: Algorithm = Algorithm(ffi::GCRY_MD_SHA512 as libc::c_int);
pub const MD_SHA224: Algorithm = Algorithm(ffi::GCRY_MD_SHA224 as libc::c_int);
pub const MD_MD4: Algorithm = Algorithm(ffi::GCRY_MD_MD4 as libc::c_int);
pub const MD_CRC32: Algorithm = Algorithm(ffi::GCRY_MD_CRC32 as libc::c_int);
pub const MD_CRC32_RFC1510: Algorithm = Algorithm(ffi::GCRY_MD_CRC32_RFC1510 as libc::c_int);
pub const MD_CRC24_RFC2440: Algorithm = Algorithm(ffi::GCRY_MD_CRC24_RFC2440 as libc::c_int);
pub const MD_WHIRLPOOL: Algorithm = Algorithm(ffi::GCRY_MD_WHIRLPOOL as libc::c_int);
pub const MD_TIGER1: Algorithm = Algorithm(ffi::GCRY_MD_TIGER1 as libc::c_int);
pub const MD_TIGER2: Algorithm = Algorithm(ffi::GCRY_MD_TIGER2 as libc::c_int);
pub const MD_GOSTR3411_94: Algorithm = Algorithm(ffi::GCRY_MD_GOSTR3411_94 as libc::c_int);
pub const MD_STRIBOG256: Algorithm = Algorithm(ffi::GCRY_MD_STRIBOG256 as libc::c_int);
pub const MD_STRIBOG512: Algorithm = Algorithm(ffi::GCRY_MD_STRIBOG512 as libc::c_int);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Algorithm(libc::c_int);

impl Algorithm {
    pub fn from_raw(raw: ffi::gcry_md_algos) -> Algorithm {
        Algorithm(raw as libc::c_int)
    }

    pub fn as_raw(&self) -> ffi::gcry_md_algos {
        self.0 as ffi::gcry_md_algos
    }

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

    pub fn is_available(&self) -> bool {
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

impl MessageDigest {
    pub unsafe fn from_raw(raw: ffi::gcry_md_hd_t) -> MessageDigest {
        MessageDigest { raw: raw }
    }

    pub fn as_raw(&self) -> ffi::gcry_md_hd_t {
        self.raw
    }

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

    pub fn set_key<B: AsRef<[u8]>>(&mut self, key: &B) -> Result<()> {
        let key = key.as_ref();
        unsafe {
            return_err!(ffi::gcry_md_setkey(self.raw, mem::transmute(key.as_ptr()),
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
            ffi::gcry_md_write(self.raw, mem::transmute(bytes.as_ptr()),
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
