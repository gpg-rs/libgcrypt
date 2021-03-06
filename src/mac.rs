use std::{
    ffi::CStr,
    io::{self, Write},
    ptr, result,
    str::Utf8Error,
};

use bitflags::bitflags;
use cstr_argument::CStrArgument;
use ffi;
use libc::c_int;

use crate::{error::return_err, NonNull, Result};

ffi_enum_wrapper! {
    #[allow(non_camel_case_types)]
    pub enum Algorithm: c_int {
        Gost28147Imit     = ffi::GCRY_MAC_GOST28147_IMIT,

        HmacSha256        = ffi::GCRY_MAC_HMAC_SHA256,
        HmacSha224        = ffi::GCRY_MAC_HMAC_SHA224,
        HmacSha512        = ffi::GCRY_MAC_HMAC_SHA512,
        HmacSha384        = ffi::GCRY_MAC_HMAC_SHA384,
        HmacSha1          = ffi::GCRY_MAC_HMAC_SHA1,
        HmacMd5           = ffi::GCRY_MAC_HMAC_MD5,
        HmacMd4           = ffi::GCRY_MAC_HMAC_MD4,
        HmacRmd160        = ffi::GCRY_MAC_HMAC_RMD160,
        HmacTiger1        = ffi::GCRY_MAC_HMAC_TIGER1,
        HmacWhirlpool     = ffi::GCRY_MAC_HMAC_WHIRLPOOL,
        HmacGostR3411_94  = ffi::GCRY_MAC_HMAC_GOSTR3411_94,
        HmacStribog256    = ffi::GCRY_MAC_HMAC_STRIBOG256,
        HmacStribog512    = ffi::GCRY_MAC_HMAC_STRIBOG512,
        HmacMd2           = ffi::GCRY_MAC_HMAC_MD2,
        HmacSha3_224      = ffi::GCRY_MAC_HMAC_SHA3_224,
        HmacSha3_256      = ffi::GCRY_MAC_HMAC_SHA3_256,
        HmacSha3_384      = ffi::GCRY_MAC_HMAC_SHA3_384,
        HmacSha3_512      = ffi::GCRY_MAC_HMAC_SHA3_512,
        HmacGostR3411Cp   = ffi::GCRY_MAC_HMAC_GOSTR3411_CP,
        HmacBlake2b512    = ffi::GCRY_MAC_HMAC_BLAKE2B_512,
        HmacBlake2b384    = ffi::GCRY_MAC_HMAC_BLAKE2B_384,
        HmacBlake2b256    = ffi::GCRY_MAC_HMAC_BLAKE2B_256,
        HmacBlake2b160    = ffi::GCRY_MAC_HMAC_BLAKE2B_160,
        HmacBlake2s256    = ffi::GCRY_MAC_HMAC_BLAKE2S_256,
        HmacBlake2s224    = ffi::GCRY_MAC_HMAC_BLAKE2S_224,
        HmacBlake2s160    = ffi::GCRY_MAC_HMAC_BLAKE2S_160,
        HmacBlake2s128    = ffi::GCRY_MAC_HMAC_BLAKE2S_128,
        HmacSm3           = ffi::GCRY_MAC_HMAC_SM3,
        HmacSha512_256    = ffi::GCRY_MAC_HMAC_SHA512_256,
        HmacSha512_224    = ffi::GCRY_MAC_HMAC_SHA512_224,

        CmacAes           = ffi::GCRY_MAC_CMAC_AES,
        Cmac3des          = ffi::GCRY_MAC_CMAC_3DES,
        CmacCamellia      = ffi::GCRY_MAC_CMAC_CAMELLIA,
        CmacCast5         = ffi::GCRY_MAC_CMAC_CAST5,
        CmacBlowfish      = ffi::GCRY_MAC_CMAC_BLOWFISH,
        CmacTwofish       = ffi::GCRY_MAC_CMAC_TWOFISH,
        CmacSerpent       = ffi::GCRY_MAC_CMAC_SERPENT,
        CmacSeed          = ffi::GCRY_MAC_CMAC_SEED,
        CmacRfc2268       = ffi::GCRY_MAC_CMAC_RFC2268,
        CmacIdea          = ffi::GCRY_MAC_CMAC_IDEA,
        CmacGost28147     = ffi::GCRY_MAC_CMAC_GOST28147,
        CmacSm4           = ffi::GCRY_MAC_CMAC_SM4,

        GmacAes           = ffi::GCRY_MAC_GMAC_AES,
        GmacCamellia      = ffi::GCRY_MAC_GMAC_CAMELLIA,
        GmacTwofish       = ffi::GCRY_MAC_GMAC_TWOFISH,
        GmacSerpent       = ffi::GCRY_MAC_GMAC_SERPENT,
        GmacSeed          = ffi::GCRY_MAC_GMAC_SEED,

        Poly1305          = ffi::GCRY_MAC_POLY1305,
        Poly1305Aes       = ffi::GCRY_MAC_POLY1305_AES,
        Poly1305Camellia  = ffi::GCRY_MAC_POLY1305_CAMELLIA,
        Poly1305Twofish   = ffi::GCRY_MAC_POLY1305_TWOFISH,
        Poly1305Serpent   = ffi::GCRY_MAC_POLY1305_SERPENT,
        Poly1305Seed      = ffi::GCRY_MAC_POLY1305_SEED,
    }
}

impl Algorithm {
    #[inline]
    pub fn from_name(name: impl CStrArgument) -> Option<Algorithm> {
        let name = name.into_cstr();
        let result = unsafe { ffi::gcry_mac_map_name(name.as_ref().as_ptr()) };
        if result != 0 {
            unsafe { Some(Algorithm::from_raw(result)) }
        } else {
            None
        }
    }

    #[inline]
    pub fn is_available(&self) -> bool {
        let _ = crate::init_default();
        unsafe { ffi::gcry_mac_test_algo(self.raw()) == 0 }
    }

    #[inline]
    pub fn name(&self) -> result::Result<&'static str, Option<Utf8Error>> {
        self.name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'static CStr> {
        unsafe {
            ffi::gcry_mac_algo_name(self.raw())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn key_len(&self) -> usize {
        unsafe { ffi::gcry_mac_get_algo_keylen(self.raw()) as usize }
    }

    #[inline]
    pub fn mac_len(&self) -> usize {
        unsafe { ffi::gcry_mac_get_algo_maclen(self.raw()) as usize }
    }
}

bitflags! {
    pub struct Flags: ffi::gcry_mac_flags {
        const NONE  = 0;
        const SECURE = ffi::GCRY_MAC_FLAG_SECURE;
    }
}

#[derive(Debug)]
pub struct Mac(NonNull<ffi::gcry_mac_hd_t>);

impl Drop for Mac {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_mac_close(self.as_raw());
        }
    }
}

impl Mac {
    impl_wrapper!(Mac: ffi::gcry_mac_hd_t);

    #[inline]
    pub fn new(algo: Algorithm) -> Result<Mac> {
        Mac::with_flags(algo, Flags::NONE)
    }

    #[inline]
    pub fn with_flags(algo: Algorithm, flags: Flags) -> Result<Mac> {
        let _ = crate::init_default();
        unsafe {
            let mut handle: ffi::gcry_mac_hd_t = ptr::null_mut();
            return_err!(ffi::gcry_mac_open(
                &mut handle,
                algo.raw(),
                flags.bits(),
                ptr::null_mut()
            ));
            Ok(Mac::from_raw(handle))
        }
    }

    #[inline]
    pub fn set_key(&mut self, key: impl AsRef<[u8]>) -> Result<()> {
        let key = key.as_ref();
        unsafe {
            return_err!(ffi::gcry_mac_setkey(
                self.as_raw(),
                key.as_ptr().cast(),
                key.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn set_iv(&mut self, iv: impl AsRef<[u8]>) -> Result<()> {
        let iv = iv.as_ref();
        unsafe {
            return_err!(ffi::gcry_mac_setiv(
                self.as_raw(),
                iv.as_ptr().cast(),
                iv.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn reset(&mut self) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_mac_reset(self.as_raw()));
        }
        Ok(())
    }

    #[inline]
    pub fn update(&mut self, bytes: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_mac_write(
                self.as_raw(),
                bytes.as_ptr().cast(),
                bytes.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn get_mac(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut len = buf.len();
        unsafe {
            return_err!(ffi::gcry_mac_read(
                self.as_raw(),
                buf.as_mut_ptr().cast(),
                &mut len
            ));
        }
        Ok(len)
    }

    #[inline]
    pub fn verify(&mut self, buf: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_mac_verify(
                self.as_raw(),
                buf.as_ptr().cast(),
                buf.len()
            ));
        }
        Ok(())
    }
}

impl Write for Mac {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf)?;
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
