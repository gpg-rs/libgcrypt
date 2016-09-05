use std::ffi::CString;
use std::io::{self, Write};
use std::ptr;
use std::slice;

use ffi;
use libc::c_int;

use Token;
use utils;
use error::Result;

enum_wrapper! {
    pub enum Algorithm: c_int {
        MD_MD5           = ffi::GCRY_MD_MD5,
        MD_SHA1          = ffi::GCRY_MD_SHA1,
        MD_RMD160        = ffi::GCRY_MD_RMD160,
        MD_MD2           = ffi::GCRY_MD_MD2,
        MD_TIGER         = ffi::GCRY_MD_TIGER,
        MD_HAVAL         = ffi::GCRY_MD_HAVAL,
        MD_SHA256        = ffi::GCRY_MD_SHA256,
        MD_SHA384        = ffi::GCRY_MD_SHA384,
        MD_SHA512        = ffi::GCRY_MD_SHA512,
        MD_SHA224        = ffi::GCRY_MD_SHA224,
        MD_MD4           = ffi::GCRY_MD_MD4,
        MD_CRC32         = ffi::GCRY_MD_CRC32,
        MD_CRC32_RFC1510 = ffi::GCRY_MD_CRC32_RFC1510,
        MD_CRC24_RFC2440 = ffi::GCRY_MD_CRC24_RFC2440,
        MD_WHIRLPOOL     = ffi::GCRY_MD_WHIRLPOOL,
        MD_TIGER1        = ffi::GCRY_MD_TIGER1,
        MD_TIGER2        = ffi::GCRY_MD_TIGER2,
        MD_GOSTR3411_94  = ffi::GCRY_MD_GOSTR3411_94,
        MD_STRIBOG256    = ffi::GCRY_MD_STRIBOG256,
        MD_STRIBOG512    = ffi::GCRY_MD_STRIBOG512,
        MD_GOSTR3411_CP  = ffi::GCRY_MD_GOSTR3411_CP,
        MD_SHA3_224      = ffi::GCRY_MD_SHA3_224,
        MD_SHA3_256      = ffi::GCRY_MD_SHA3_256,
        MD_SHA3_384      = ffi::GCRY_MD_SHA3_384,
        MD_SHA3_512      = ffi::GCRY_MD_SHA3_512,
        MD_SHAKE128      = ffi::GCRY_MD_SHAKE128,
        MD_SHAKE256      = ffi::GCRY_MD_SHAKE256,
    }
}

impl Algorithm {
    pub fn from_name<S: Into<String>>(name: S) -> Option<Algorithm> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe { ffi::gcry_md_map_name(name.as_ptr()) };
        if result != 0 {
            Some(Algorithm(result))
        } else {
            None
        }
    }

    pub fn is_available(&self, _: Token) -> bool {
        unsafe { ffi::gcry_md_test_algo(self.0) == 0 }
    }

    pub fn name(&self) -> Option<&'static str> {
        unsafe { utils::from_cstr(ffi::gcry_md_algo_name(self.0)) }
    }

    pub fn digest_len(&self) -> usize {
        unsafe { ffi::gcry_md_get_algo_dlen(self.0) as usize }
    }
}

bitflags! {
    flags Flags: ffi::gcry_md_flags {
        const FLAGS_NONE   = 0,
        const FLAG_SECURE  = ffi::GCRY_MD_FLAG_SECURE,
        const FLAG_HMAC    = ffi::GCRY_MD_FLAG_HMAC,
        const FLAG_BUGEMU1 = ffi::GCRY_MD_FLAG_BUGEMU1,
    }
}

#[derive(Debug)]
pub struct MessageDigest(ffi::gcry_md_hd_t);

impl_wrapper!(MessageDigest: ffi::gcry_md_hd_t);

impl Drop for MessageDigest {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_md_close(self.0);
        }
    }
}

impl MessageDigest {
    pub fn new(token: Token, algo: Algorithm) -> Result<MessageDigest> {
        MessageDigest::with_flags(token, algo, FLAGS_NONE)
    }

    pub fn with_flags(_: Token, algo: Algorithm, flags: Flags) -> Result<MessageDigest> {
        let mut handle: ffi::gcry_md_hd_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_md_open(&mut handle, algo.0, flags.bits()));
            Ok(MessageDigest::from_raw(handle))
        }
    }

    pub fn try_clone(&self) -> Result<MessageDigest> {
        let mut handle: ffi::gcry_md_hd_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_md_copy(&mut handle, self.0));
            Ok(MessageDigest::from_raw(handle))
        }
    }

    pub fn enable(&mut self, algo: Algorithm) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_md_enable(self.0, algo.0));
        }
        Ok(())
    }

    pub fn is_enabled(&self, algo: Algorithm) -> bool {
        unsafe { ffi::gcry_md_is_enabled(self.0, algo.0) != 0 }
    }

    pub fn is_secure(&self) -> bool {
        unsafe { ffi::gcry_md_is_secure(self.0) != 0 }
    }

    pub fn set_key<B: AsRef<[u8]>>(&mut self, key: B) -> Result<()> {
        let key = key.as_ref();
        unsafe {
            return_err!(ffi::gcry_md_setkey(self.0, key.as_ptr() as *const _, key.len()));
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        unsafe { ffi::gcry_md_reset(self.0) }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::gcry_md_write(self.0, bytes.as_ptr() as *const _, bytes.len());
        }
    }

    pub fn finish(&mut self) {
        unsafe {
            ffi::gcry_md_final(self.0);
        }
    }

    pub fn get_only_digest(&mut self) -> Option<&[u8]> {
        let algo = unsafe { ffi::gcry_md_get_algo(self.0) };
        if algo != 0 {
            self.get_digest(Algorithm(algo))
        } else {
            None
        }
    }

    pub fn get_digest(&mut self, algo: Algorithm) -> Option<&[u8]> {
        let len = algo.digest_len();
        if len == 0 {
            return None;
        }

        unsafe {
            ffi::gcry_md_read(self.0, algo.0).as_ref().map(|x| slice::from_raw_parts(x, len))
        }
    }
}

impl Write for MessageDigest {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn hash(token: Token, algo: Algorithm, src: &[u8], dst: &mut [u8]) {
    assert!(algo.is_available(token));
    assert!(dst.len() >= algo.digest_len());
    unsafe {
        ffi::gcry_md_hash_buffer(algo.0,
                                 dst.as_mut_ptr() as *mut _,
                                 src.as_ptr() as *const _,
                                 src.len().into());
    }
}
