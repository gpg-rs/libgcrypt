use std::ffi::CString;
use std::ptr;

use ffi;
use libc::c_int;

use Token;
use utils;
use error::Result;

enum_wrapper! {
    pub enum Algorithm: c_int {
        CIPHER_IDEA        = ffi::GCRY_CIPHER_IDEA,
        CIPHER_3DES        = ffi::GCRY_CIPHER_3DES,
        CIPHER_CAST5       = ffi::GCRY_CIPHER_CAST5,
        CIPHER_BLOWFISH    = ffi::GCRY_CIPHER_BLOWFISH,
        CIPHER_SAFER_SK128 = ffi::GCRY_CIPHER_SAFER_SK128,
        CIPHER_DES_SK      = ffi::GCRY_CIPHER_DES_SK,
        CIPHER_AES         = ffi::GCRY_CIPHER_AES,
        CIPHER_AES128      = ffi::GCRY_CIPHER_AES128,
        CIPHER_AES192      = ffi::GCRY_CIPHER_AES192,
        CIPHER_AES256      = ffi::GCRY_CIPHER_AES256,
        CIPHER_RIJNDAEL    = ffi::GCRY_CIPHER_RIJNDAEL,
        CIPHER_RIJNDAEL128 = ffi::GCRY_CIPHER_RIJNDAEL128,
        CIPHER_RIJNDAEL192 = ffi::GCRY_CIPHER_RIJNDAEL192,
        CIPHER_RIJNDAEL256 = ffi::GCRY_CIPHER_RIJNDAEL256,
        CIPHER_TWOFISH     = ffi::GCRY_CIPHER_TWOFISH,
        CIPHER_ARCFOUR     = ffi::GCRY_CIPHER_ARCFOUR,
        CIPHER_DES         = ffi::GCRY_CIPHER_DES,
        CIPHER_TWOFISH128  = ffi::GCRY_CIPHER_TWOFISH128,
        CIPHER_SERPENT128  = ffi::GCRY_CIPHER_SERPENT128,
        CIPHER_SERPENT192  = ffi::GCRY_CIPHER_SERPENT192,
        CIPHER_SERPENT256  = ffi::GCRY_CIPHER_SERPENT256,
        CIPHER_RFC2268_40  = ffi::GCRY_CIPHER_RFC2268_40,
        CIPHER_RFC2268_128 = ffi::GCRY_CIPHER_RFC2268_128,
        CIPHER_SEED        = ffi::GCRY_CIPHER_SEED,
        CIPHER_CAMELLIA128 = ffi::GCRY_CIPHER_CAMELLIA128,
        CIPHER_CAMELLIA192 = ffi::GCRY_CIPHER_CAMELLIA192,
        CIPHER_CAMELLIA256 = ffi::GCRY_CIPHER_CAMELLIA256,
        CIPHER_SALSA20     = ffi::GCRY_CIPHER_SALSA20,
        CIPHER_SALSA20R12  = ffi::GCRY_CIPHER_SALSA20R12,
        CIPHER_GOST28147   = ffi::GCRY_CIPHER_GOST28147,
        CIPHER_CHACHA20    = ffi::GCRY_CIPHER_CHACHA20,
    }
}

impl Algorithm {
    pub fn from_name<S: Into<String>>(name: S) -> Option<Algorithm> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe { ffi::gcry_cipher_map_name(name.as_ptr()) };
        if result != 0 {
            Some(Algorithm(result))
        } else {
            None
        }
    }

    pub fn is_available(&self, _: Token) -> bool {
        unsafe {
            ffi::gcry_cipher_test_algo(self.0) == 0
        }
    }

    pub fn name(&self) -> Option<&'static str> {
        unsafe { utils::from_cstr(ffi::gcry_cipher_algo_name(self.0)) }
    }

    pub fn key_len(&self) -> usize {
        unsafe { ffi::gcry_cipher_get_algo_keylen(self.0) }
    }

    pub fn block_len(&self) -> usize {
        unsafe { ffi::gcry_cipher_get_algo_blklen(self.0) }
    }
}

enum_wrapper! {
    pub enum Mode: c_int {
        MODE_ECB      = ffi::GCRY_CIPHER_MODE_ECB,
        MODE_CFB      = ffi::GCRY_CIPHER_MODE_CFB,
        MODE_CBC      = ffi::GCRY_CIPHER_MODE_CBC,
        MODE_STREAM   = ffi::GCRY_CIPHER_MODE_STREAM,
        MODE_OFB      = ffi::GCRY_CIPHER_MODE_OFB,
        MODE_CTR      = ffi::GCRY_CIPHER_MODE_CTR,
        MODE_AESWRAP  = ffi::GCRY_CIPHER_MODE_AESWRAP,
        MODE_CCM      = ffi::GCRY_CIPHER_MODE_CCM,
        MODE_GCM      = ffi::GCRY_CIPHER_MODE_GCM,
        MODE_POLY1305 = ffi::GCRY_CIPHER_MODE_POLY1305,
        MODE_OCB      = ffi::GCRY_CIPHER_MODE_OCB,
        MODE_CFB8     = ffi::GCRY_CIPHER_MODE_CFB8,
    }
}

impl Mode {
    pub fn from_oid<S: Into<String>>(name: S) -> Option<Mode> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe { ffi::gcry_cipher_mode_from_oid(name.as_ptr()) };
        if result != 0 {
            Some(Mode(result))
        } else {
            None
        }
    }
}

bitflags! {
    flags Flags: ffi::gcry_cipher_flags {
        const FLAGS_NONE       = 0,
        const FLAG_SECURE      = ffi::GCRY_CIPHER_SECURE,
        const FLAG_ENABLE_SYNC = ffi::GCRY_CIPHER_ENABLE_SYNC,
        const FLAG_CBC_CTS     = ffi::GCRY_CIPHER_CBC_CTS,
        const FLAG_CBC_MAC     = ffi::GCRY_CIPHER_CBC_MAC,
    }
}

#[derive(Debug)]
pub struct Cipher(ffi::gcry_cipher_hd_t);

impl_wrapper!(Cipher: ffi::gcry_cipher_hd_t);

impl Drop for Cipher {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_cipher_close(self.0);
        }
    }
}

impl Cipher {
    pub fn new(_: Token, algo: Algorithm, mode: Mode, flags: Flags) -> Result<Cipher> {
        let mut handle: ffi::gcry_cipher_hd_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_cipher_open(&mut handle, algo.0, mode.0, flags.bits()));
            Ok(Cipher::from_raw(handle))
        }
    }

    pub fn set_key(&mut self, key: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_setkey(self.0, key.as_ptr() as *const _, key.len()));
        }
        Ok(())
    }

    pub fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_setiv(self.0, iv.as_ptr() as *const _, iv.len()));
        }
        Ok(())
    }

    pub fn set_ctr(&mut self, ctr: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_setctr(self.0, ctr.as_ptr() as *const _, ctr.len()));
        }
        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_reset(self.0));
        }
        Ok(())
    }

    pub fn authenticate(&mut self, bytes: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_authenticate(self.0,
                                                      bytes.as_ptr() as *const _,
                                                      bytes.len()));
        }
        Ok(())
    }

    pub fn get_tag(&mut self, tag: &mut [u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_gettag(self.0, tag.as_mut_ptr() as *mut _, tag.len()));
        }
        Ok(())
    }

    pub fn check_tag(&mut self, tag: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_checktag(self.0, tag.as_ptr() as *const _, tag.len()));
        }
        Ok(())
    }

    pub fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_encrypt(self.0,
                                                 output.as_mut_ptr() as *mut _,
                                                 output.len(),
                                                 input.as_ptr() as *const _,
                                                 input.len()));
        }
        Ok(())
    }

    pub fn decrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_decrypt(self.0,
                                                 output.as_mut_ptr() as *mut _,
                                                 output.len(),
                                                 input.as_ptr() as *const _,
                                                 input.len()));
        }
        Ok(())
    }

    pub fn encrypt_inplace(&mut self, plain: &mut [u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_encrypt(self.0,
                                                 pain.as_mut_ptr() as *mut _,
                                                 pain.len(),
                                                 ptr::null(),
                                                 0));
        }
        Ok(())
    }

    pub fn decrypt_inplace(&mut self, cipher: &mut [u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_decrypt(self.0,
                                                 cipher.as_mut_ptr() as *mut _,
                                                 cipher.len(),
                                                 ptr::null(),
                                                 0));
        }
        Ok(())
    }
}
