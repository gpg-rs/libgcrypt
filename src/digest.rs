use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::ptr;
use std::result;
use std::slice;
use std::str::Utf8Error;

use ffi;
use libc::c_int;

use {NonZero, Result};

ffi_enum_wrapper! {
    #[allow(non_camel_case_types)]
    pub enum Algorithm: c_int {
        Md5           = ffi::GCRY_MD_MD5,
        Sha1          = ffi::GCRY_MD_SHA1,
        Rmd160        = ffi::GCRY_MD_RMD160,
        Md2           = ffi::GCRY_MD_MD2,
        Tiger         = ffi::GCRY_MD_TIGER,
        Haval         = ffi::GCRY_MD_HAVAL,
        Sha256        = ffi::GCRY_MD_SHA256,
        Sha384        = ffi::GCRY_MD_SHA384,
        Sha512        = ffi::GCRY_MD_SHA512,
        Sha224        = ffi::GCRY_MD_SHA224,
        Md4           = ffi::GCRY_MD_MD4,
        Crc32         = ffi::GCRY_MD_CRC32,
        Crc32Rfc1510 = ffi::GCRY_MD_CRC32_RFC1510,
        Crc24Rfc2440 = ffi::GCRY_MD_CRC24_RFC2440,
        Whirlpool     = ffi::GCRY_MD_WHIRLPOOL,
        Tiger1        = ffi::GCRY_MD_TIGER1,
        Tiger2        = ffi::GCRY_MD_TIGER2,
        GostR3411_94  = ffi::GCRY_MD_GOSTR3411_94,
        Stribog256    = ffi::GCRY_MD_STRIBOG256,
        Stribog512    = ffi::GCRY_MD_STRIBOG512,
        Gostr3411Cp  = ffi::GCRY_MD_GOSTR3411_CP,
        Sha3_224      = ffi::GCRY_MD_SHA3_224,
        Sha3_256      = ffi::GCRY_MD_SHA3_256,
        Sha3_384      = ffi::GCRY_MD_SHA3_384,
        Sha3_512      = ffi::GCRY_MD_SHA3_512,
        Shake128      = ffi::GCRY_MD_SHAKE128,
        Shake256      = ffi::GCRY_MD_SHAKE256,
    }
}

impl Algorithm {
    pub fn from_name<S: Into<String>>(name: S) -> Option<Algorithm> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe { ffi::gcry_md_map_name(name.as_ptr()) };
        if result != 0 {
            unsafe { Some(Algorithm::from_raw(result)) }
        } else {
            None
        }
    }

    pub fn is_available(&self) -> bool {
        let _ = ::get_token();
        unsafe { ffi::gcry_md_test_algo(self.raw()) == 0 }
    }

    pub fn name(&self) -> result::Result<&'static str, Option<Utf8Error>> {
        self.name_raw().map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    pub fn name_raw(&self) -> Option<&'static CStr> {
        unsafe {
            ffi::gcry_md_algo_name(self.raw()).as_ref().map(|s| CStr::from_ptr(s))
        }
    }

    pub fn digest_len(&self) -> usize {
        unsafe { ffi::gcry_md_get_algo_dlen(self.raw()) as usize }
    }
}

bitflags! {
    pub flags Flags: ffi::gcry_md_flags {
        const FLAGS_NONE   = 0,
        const FLAG_SECURE  = ffi::GCRY_MD_FLAG_SECURE,
        const FLAG_HMAC    = ffi::GCRY_MD_FLAG_HMAC,
        const FLAG_BUGEMU1 = ffi::GCRY_MD_FLAG_BUGEMU1,
    }
}

#[derive(Debug)]
pub struct MessageDigest(NonZero<ffi::gcry_md_hd_t>);

impl Drop for MessageDigest {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_md_close(self.as_raw());
        }
    }
}

impl MessageDigest {
    impl_wrapper!(MessageDigest: ffi::gcry_md_hd_t);

    pub fn new(algo: Algorithm) -> Result<MessageDigest> {
        MessageDigest::with_flags(algo, FLAGS_NONE)
    }

    pub fn with_flags(algo: Algorithm, flags: Flags) -> Result<MessageDigest> {
        let _ = ::get_token();
        unsafe {
            let mut handle: ffi::gcry_md_hd_t = ptr::null_mut();
            return_err!(ffi::gcry_md_open(&mut handle, algo.raw(), flags.bits()));
            Ok(MessageDigest::from_raw(handle))
        }
    }

    pub fn try_clone(&self) -> Result<MessageDigest> {
        let mut handle: ffi::gcry_md_hd_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_md_copy(&mut handle, self.as_raw()));
            Ok(MessageDigest::from_raw(handle))
        }
    }

    pub fn enable(&mut self, algo: Algorithm) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_md_enable(self.as_raw(), algo.raw()));
        }
        Ok(())
    }

    pub fn is_enabled(&self, algo: Algorithm) -> bool {
        unsafe { ffi::gcry_md_is_enabled(self.as_raw(), algo.raw()) != 0 }
    }

    pub fn is_secure(&self) -> bool {
        unsafe { ffi::gcry_md_is_secure(self.as_raw()) != 0 }
    }

    pub fn set_key<B: AsRef<[u8]>>(&mut self, key: B) -> Result<()> {
        let key = key.as_ref();
        unsafe {
            return_err!(ffi::gcry_md_setkey(self.as_raw(), key.as_ptr() as *const _, key.len()));
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        unsafe { ffi::gcry_md_reset(self.as_raw()) }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        unsafe {
            ffi::gcry_md_write(self.as_raw(), bytes.as_ptr() as *const _, bytes.len());
        }
    }

    pub fn finish(&mut self) {
        unsafe {
            ffi::gcry_md_final(self.as_raw());
        }
    }

    pub fn get_only_digest(&mut self) -> Option<&[u8]> {
        let algo = unsafe { ffi::gcry_md_get_algo(self.as_raw()) };
        if algo != 0 {
            unsafe { self.get_digest(Algorithm::from_raw(algo)) }
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
            ffi::gcry_md_read(self.as_raw(), algo.raw())
                .as_ref()
                .map(|x| slice::from_raw_parts(x, len))
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

pub fn hash(algo: Algorithm, src: &[u8], dst: &mut [u8]) {
    assert!(algo.is_available());
    assert!(dst.len() >= algo.digest_len());
    let _ = ::get_token();
    unsafe {
        ffi::gcry_md_hash_buffer(algo.raw(),
                                 dst.as_mut_ptr() as *mut _,
                                 src.as_ptr() as *const _,
                                 src.len().into());
    }
}
