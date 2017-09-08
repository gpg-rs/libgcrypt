use std::ffi::{CStr, CString};
use std::ptr;
use std::result;
use std::str::Utf8Error;

use ffi;
use libc::c_int;

use {NonZero, Result};

ffi_enum_wrapper! {
    #[allow(non_camel_case_types)]
    pub enum Algorithm: c_int {
        Idea             = ffi::GCRY_CIPHER_IDEA,
        TripleDes        = ffi::GCRY_CIPHER_3DES,
        Cast5            = ffi::GCRY_CIPHER_CAST5,
        Blowfish         = ffi::GCRY_CIPHER_BLOWFISH,
        SaferSk128       = ffi::GCRY_CIPHER_SAFER_SK128,
        DesSk            = ffi::GCRY_CIPHER_DES_SK,
        Aes              = ffi::GCRY_CIPHER_AES,
        Aes128           = ffi::GCRY_CIPHER_AES128,
        Aes192           = ffi::GCRY_CIPHER_AES192,
        Aes256           = ffi::GCRY_CIPHER_AES256,
        Rijndael         = ffi::GCRY_CIPHER_RIJNDAEL,
        Rijndael128      = ffi::GCRY_CIPHER_RIJNDAEL128,
        Rijndael192      = ffi::GCRY_CIPHER_RIJNDAEL192,
        Rijndael256      = ffi::GCRY_CIPHER_RIJNDAEL256,
        Twofish          = ffi::GCRY_CIPHER_TWOFISH,
        Arcfour          = ffi::GCRY_CIPHER_ARCFOUR,
        Des              = ffi::GCRY_CIPHER_DES,
        Twofish128       = ffi::GCRY_CIPHER_TWOFISH128,
        Serpent128       = ffi::GCRY_CIPHER_SERPENT128,
        Serpent192       = ffi::GCRY_CIPHER_SERPENT192,
        Serpent256       = ffi::GCRY_CIPHER_SERPENT256,
        Rfc2268_40       = ffi::GCRY_CIPHER_RFC2268_40,
        Rfc2268_128      = ffi::GCRY_CIPHER_RFC2268_128,
        Seed             = ffi::GCRY_CIPHER_SEED,
        Camellia128      = ffi::GCRY_CIPHER_CAMELLIA128,
        Camellia192      = ffi::GCRY_CIPHER_CAMELLIA192,
        Camellia256      = ffi::GCRY_CIPHER_CAMELLIA256,
        Salsa20          = ffi::GCRY_CIPHER_SALSA20,
        Salsa20r12       = ffi::GCRY_CIPHER_SALSA20R12,
        Gost28147        = ffi::GCRY_CIPHER_GOST28147,
        Chacha20         = ffi::GCRY_CIPHER_CHACHA20,
    }
}

impl Algorithm {
    #[inline]
    pub fn from_name<S: Into<String>>(name: S) -> Option<Algorithm> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe { ffi::gcry_cipher_map_name(name.as_ptr()) };
        if result != 0 {
            unsafe { Some(Algorithm::from_raw(result)) }
        } else {
            None
        }
    }

    #[inline]
    pub fn is_available(&self) -> bool {
        let _ = ::get_token();
        unsafe { ffi::gcry_cipher_test_algo(self.raw()) == 0 }
    }

    #[inline]
    pub fn name(&self) -> result::Result<&'static str, Option<Utf8Error>> {
        self.name_raw()
            .map_or(Err(None), |s| s.to_str().map_err(Some))
    }

    #[inline]
    pub fn name_raw(&self) -> Option<&'static CStr> {
        unsafe {
            ffi::gcry_cipher_algo_name(self.raw())
                .as_ref()
                .map(|s| CStr::from_ptr(s))
        }
    }

    #[inline]
    pub fn key_len(&self) -> usize {
        unsafe { ffi::gcry_cipher_get_algo_keylen(self.raw()) }
    }

    #[inline]
    pub fn block_len(&self) -> usize {
        unsafe { ffi::gcry_cipher_get_algo_blklen(self.raw()) }
    }
}

ffi_enum_wrapper! {
    pub enum Mode: c_int {
        Ecb      = ffi::GCRY_CIPHER_MODE_ECB,
        Cfb      = ffi::GCRY_CIPHER_MODE_CFB,
        Cbc      = ffi::GCRY_CIPHER_MODE_CBC,
        Stream   = ffi::GCRY_CIPHER_MODE_STREAM,
        Ofb      = ffi::GCRY_CIPHER_MODE_OFB,
        Ctr      = ffi::GCRY_CIPHER_MODE_CTR,
        AesWrap  = ffi::GCRY_CIPHER_MODE_AESWRAP,
        Ccm      = ffi::GCRY_CIPHER_MODE_CCM,
        Gcm      = ffi::GCRY_CIPHER_MODE_GCM,
        Poly1305 = ffi::GCRY_CIPHER_MODE_POLY1305,
        Ocb      = ffi::GCRY_CIPHER_MODE_OCB,
        Cfb8     = ffi::GCRY_CIPHER_MODE_CFB8,
        Xts      = ffi::GCRY_CIPHER_MODE_XTS,
    }
}

impl Mode {
    #[inline]
    pub fn from_oid<S: Into<String>>(name: S) -> Option<Mode> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe { ffi::gcry_cipher_mode_from_oid(name.as_ptr()) };
        if result != 0 {
            unsafe { Some(Mode::from_raw(result)) }
        } else {
            None
        }
    }
}

bitflags! {
    pub struct Flags: ffi::gcry_cipher_flags {
        const FLAGS_NONE       = 0;
        const FLAG_SECURE      = ffi::GCRY_CIPHER_SECURE;
        const FLAG_ENABLE_SYNC = ffi::GCRY_CIPHER_ENABLE_SYNC;
        const FLAG_CBC_CTS     = ffi::GCRY_CIPHER_CBC_CTS;
        const FLAG_CBC_MAC     = ffi::GCRY_CIPHER_CBC_MAC;
    }
}

#[derive(Debug)]
pub struct Cipher(NonZero<ffi::gcry_cipher_hd_t>);

impl Drop for Cipher {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_cipher_close(self.as_raw());
        }
    }
}

impl Cipher {
    impl_wrapper!(Cipher: ffi::gcry_cipher_hd_t);

    #[inline]
    pub fn new(algo: Algorithm, mode: Mode) -> Result<Cipher> {
        Cipher::with_flags(algo, mode, FLAGS_NONE)
    }

    #[inline]
    pub fn with_flags(algo: Algorithm, mode: Mode, flags: Flags) -> Result<Cipher> {
        let _ = ::get_token();
        unsafe {
            let mut handle: ffi::gcry_cipher_hd_t = ptr::null_mut();
            return_err!(ffi::gcry_cipher_open(
                &mut handle,
                algo.raw(),
                mode.raw(),
                flags.bits()
            ));
            Ok(Cipher::from_raw(handle))
        }
    }

    #[inline]
    pub fn set_key<B: AsRef<[u8]>>(&mut self, key: B) -> Result<()> {
        let key = key.as_ref();
        unsafe {
            return_err!(ffi::gcry_cipher_setkey(
                self.as_raw(),
                key.as_ptr() as *const _,
                key.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn set_iv<B: AsRef<[u8]>>(&mut self, iv: B) -> Result<()> {
        let iv = iv.as_ref();
        unsafe {
            return_err!(ffi::gcry_cipher_setiv(
                self.as_raw(),
                iv.as_ptr() as *const _,
                iv.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn set_ctr<B: AsRef<[u8]>>(&mut self, ctr: B) -> Result<()> {
        let ctr = ctr.as_ref();
        unsafe {
            return_err!(ffi::gcry_cipher_setctr(
                self.as_raw(),
                ctr.as_ptr() as *const _,
                ctr.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn reset(&mut self) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_reset(self.as_raw()));
        }
        Ok(())
    }

    #[inline]
    pub fn authenticate(&mut self, bytes: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_authenticate(
                self.as_raw(),
                bytes.as_ptr() as *const _,
                bytes.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn get_tag(&mut self, tag: &mut [u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_gettag(
                self.as_raw(),
                tag.as_mut_ptr() as *mut _,
                tag.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn verify_tag(&mut self, tag: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_checktag(
                self.as_raw(),
                tag.as_ptr() as *const _,
                tag.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_encrypt(
                self.as_raw(),
                output.as_mut_ptr() as *mut _,
                output.len(),
                input.as_ptr() as *const _,
                input.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn decrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_decrypt(
                self.as_raw(),
                output.as_mut_ptr() as *mut _,
                output.len(),
                input.as_ptr() as *const _,
                input.len()
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn encrypt_inplace(&mut self, buffer: &mut [u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_encrypt(
                self.as_raw(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                ptr::null(),
                0
            ));
        }
        Ok(())
    }

    #[inline]
    pub fn decrypt_inplace(&mut self, buffer: &mut [u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_decrypt(
                self.as_raw(),
                buffer.as_mut_ptr() as *mut _,
                buffer.len(),
                ptr::null(),
                0
            ));
        }
        Ok(())
    }
}
