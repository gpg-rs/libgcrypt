use std::ffi::CString;
use std::mem;
use std::ptr;

use libc;
use ffi;

use Token;
use utils;
use error::Result;

pub const CIPHER_IDEA: Algorithm = Algorithm(ffi::GCRY_CIPHER_IDEA as libc::c_int);
pub const CIPHER_3DES: Algorithm = Algorithm(ffi::GCRY_CIPHER_3DES as libc::c_int);
pub const CIPHER_CAST5: Algorithm = Algorithm(ffi::GCRY_CIPHER_CAST5 as libc::c_int);
pub const CIPHER_BLOWFISH: Algorithm = Algorithm(ffi::GCRY_CIPHER_BLOWFISH as libc::c_int);
pub const CIPHER_SAFER_SK128: Algorithm = Algorithm(ffi::GCRY_CIPHER_SAFER_SK128 as libc::c_int);
pub const CIPHER_DES_SK: Algorithm = Algorithm(ffi::GCRY_CIPHER_DES_SK as libc::c_int);
pub const CIPHER_AES: Algorithm = Algorithm(ffi::GCRY_CIPHER_AES as libc::c_int);
pub const CIPHER_AES192: Algorithm = Algorithm(ffi::GCRY_CIPHER_AES192 as libc::c_int);
pub const CIPHER_AES256: Algorithm = Algorithm(ffi::GCRY_CIPHER_AES256 as libc::c_int);
pub const CIPHER_TWOFISH: Algorithm = Algorithm(ffi::GCRY_CIPHER_TWOFISH as libc::c_int);
pub const CIPHER_ARCFOUR: Algorithm = Algorithm(ffi::GCRY_CIPHER_ARCFOUR as libc::c_int);
pub const CIPHER_DES: Algorithm = Algorithm(ffi::GCRY_CIPHER_DES as libc::c_int);
pub const CIPHER_TWOFISH128: Algorithm = Algorithm(ffi::GCRY_CIPHER_TWOFISH128 as libc::c_int);
pub const CIPHER_SERPENT128: Algorithm = Algorithm(ffi::GCRY_CIPHER_SERPENT128 as libc::c_int);
pub const CIPHER_SERPENT192: Algorithm = Algorithm(ffi::GCRY_CIPHER_SERPENT192 as libc::c_int);
pub const CIPHER_SERPENT256: Algorithm = Algorithm(ffi::GCRY_CIPHER_SERPENT256 as libc::c_int);
pub const CIPHER_RFC2268_40: Algorithm = Algorithm(ffi::GCRY_CIPHER_RFC2268_40 as libc::c_int);
pub const CIPHER_RFC2268_128: Algorithm = Algorithm(ffi::GCRY_CIPHER_RFC2268_128 as libc::c_int);
pub const CIPHER_SEED: Algorithm = Algorithm(ffi::GCRY_CIPHER_SEED as libc::c_int);
pub const CIPHER_CAMELLIA128: Algorithm = Algorithm(ffi::GCRY_CIPHER_CAMELLIA128 as libc::c_int);
pub const CIPHER_CAMELLIA192: Algorithm = Algorithm(ffi::GCRY_CIPHER_CAMELLIA192 as libc::c_int);
pub const CIPHER_CAMELLIA256: Algorithm = Algorithm(ffi::GCRY_CIPHER_CAMELLIA256 as libc::c_int);
pub const CIPHER_SALSA20: Algorithm = Algorithm(ffi::GCRY_CIPHER_SALSA20 as libc::c_int);
pub const CIPHER_SALSA20R12: Algorithm = Algorithm(ffi::GCRY_CIPHER_SALSA20R12 as libc::c_int);
pub const CIPHER_GOST28147: Algorithm = Algorithm(ffi::GCRY_CIPHER_GOST28147 as libc::c_int);
pub const CIPHER_AES128: Algorithm = Algorithm(ffi::GCRY_CIPHER_AES128 as libc::c_int);
pub const CIPHER_RIJNDAEL: Algorithm = Algorithm(ffi::GCRY_CIPHER_RIJNDAEL as libc::c_int);
pub const CIPHER_RIJNDAEL128: Algorithm = Algorithm(ffi::GCRY_CIPHER_RIJNDAEL128 as libc::c_int);
pub const CIPHER_RIJNDAEL192: Algorithm = Algorithm(ffi::GCRY_CIPHER_RIJNDAEL192 as libc::c_int);
pub const CIPHER_RIJNDAEL256: Algorithm = Algorithm(ffi::GCRY_CIPHER_RIJNDAEL256 as libc::c_int);

pub const MODE_ECB: Mode = Mode(ffi::GCRY_CIPHER_MODE_ECB as libc::c_int);
pub const MODE_CFB: Mode = Mode(ffi::GCRY_CIPHER_MODE_CFB as libc::c_int);
pub const MODE_CBC: Mode = Mode(ffi::GCRY_CIPHER_MODE_CBC as libc::c_int);
pub const MODE_STREAM: Mode = Mode(ffi::GCRY_CIPHER_MODE_STREAM as libc::c_int);
pub const MODE_OFB: Mode = Mode(ffi::GCRY_CIPHER_MODE_OFB as libc::c_int);
pub const MODE_CTR: Mode = Mode(ffi::GCRY_CIPHER_MODE_CTR as libc::c_int);
pub const MODE_AESWRAP: Mode = Mode(ffi::GCRY_CIPHER_MODE_AESWRAP as libc::c_int);
pub const MODE_CCM: Mode = Mode(ffi::GCRY_CIPHER_MODE_CCM as libc::c_int);
pub const MODE_GCM: Mode = Mode(ffi::GCRY_CIPHER_MODE_GCM as libc::c_int);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Algorithm(libc::c_int);

impl Algorithm {
    pub fn from_raw(raw: ffi::gcry_cipher_algos) -> Algorithm {
        Algorithm(raw as libc::c_int)
    }

    pub fn as_raw(&self) -> ffi::gcry_cipher_algos {
        self.0 as ffi::gcry_cipher_algos
    }

    pub fn from_name<S: Into<String>>(name: S) -> Option<Algorithm> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe {
            ffi::gcry_cipher_map_name(name.as_ptr())
        };
        if result != 0 {
            Some(Algorithm(result))
        } else {
            None
        }
    }

    pub fn is_available(&self) -> bool {
        unsafe {
            ffi::gcry_cipher_algo_info(self.0, ffi::GCRYCTL_TEST_ALGO as libc::c_int,
                                       ptr::null_mut(), ptr::null_mut()) == 0
        }
    }

    pub fn name(&self) -> &'static str {
        unsafe {
            utils::from_cstr(ffi::gcry_cipher_algo_name(self.0)).unwrap()
        }
    }

    pub fn key_len(&self) -> usize {
        unsafe {
            ffi::gcry_cipher_get_algo_keylen(self.0) as usize
        }
    }

    pub fn block_len(&self) -> usize {
        unsafe {
            ffi::gcry_cipher_get_algo_blklen(self.0) as usize
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Mode(libc::c_int);

impl Mode {
    pub fn from_raw(raw: ffi::gcry_cipher_modes) -> Mode {
        Mode(raw as libc::c_int)
    }

    pub fn as_raw(&self) -> ffi::gcry_cipher_modes {
        self.0 as ffi::gcry_cipher_modes
    }

    pub fn from_oid<S: Into<String>>(name: S) -> Option<Mode> {
        let name = try_opt!(CString::new(name.into()).ok());
        let result = unsafe {
            ffi::gcry_cipher_mode_from_oid(name.as_ptr())
        };
        if result != 0 {
            Some(Mode(result))
        } else {
            None
        }
    }
}

bitflags! {
    flags Flags: ffi::gcry_cipher_flags {
        const FLAG_SECURE = ffi::GCRY_CIPHER_SECURE,
        const FLAG_ENABLE_SYNC = ffi::GCRY_CIPHER_ENABLE_SYNC,
        const FLAG_CBC_CTS = ffi::GCRY_CIPHER_CBC_CTS,
        const FLAG_CBC_MAC = ffi::GCRY_CIPHER_CBC_MAC,
    }
}

#[derive(Debug)]
pub struct Cipher {
    raw: ffi::gcry_cipher_hd_t,
}

impl Drop for Cipher {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_cipher_close(self.raw);
        }
    }
}

impl Cipher {
    pub unsafe fn from_raw(raw: ffi::gcry_cipher_hd_t) -> Cipher {
        Cipher { raw: raw }
    }

    pub fn as_raw(&self) -> ffi::gcry_cipher_hd_t {
        self.raw
    }

    pub fn new(_: Token, algo: Algorithm, mode: Mode, flags: Flags) -> Result<Cipher> {
        let mut handle: ffi::gcry_cipher_hd_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_cipher_open(&mut handle, algo.0, mode.0,
                                              flags.bits()));
        }
        Ok(Cipher { raw: handle })
    }

    pub fn set_key<B: AsRef<[u8]>>(&mut self, key: &B) -> Result<()> {
        let key = key.as_ref();
        unsafe {
            return_err!(ffi::gcry_cipher_setkey(self.raw, mem::transmute(key.as_ptr()),
                                                key.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn set_iv<B: AsRef<[u8]>>(&mut self, iv: &B) -> Result<()> {
        let iv = iv.as_ref();
        unsafe {
            return_err!(ffi::gcry_cipher_setiv(self.raw, mem::transmute(iv.as_ptr()),
                                               iv.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn set_ctr<B: AsRef<[u8]>>(&mut self, ctr: &B) -> Result<()> {
        let ctr = ctr.as_ref();
        unsafe {
            return_err!(ffi::gcry_cipher_setctr(self.raw, mem::transmute(ctr.as_ptr()),
                                                ctr.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn reset(&mut self) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_ctl(self.raw, ffi::GCRYCTL_RESET as libc::c_int,
                                             ptr::null_mut(), 0));
        }
        Ok(())
    }

    pub fn authenticate(&mut self, bytes: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_authenticate(self.raw, mem::transmute(bytes.as_ptr()),
                                                      bytes.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn get_tag(&mut self, tag: &mut [u8]) -> Result<()> {
        unsafe {
            let tag = (mem::transmute(tag.as_mut_ptr()), tag.len());
            return_err!(ffi::gcry_cipher_gettag(self.raw, tag.0, tag.1 as libc::size_t));
        }
        Ok(())
    }

    pub fn check_tag(&mut self, tag: &[u8]) -> Result<()> {
        unsafe {
            return_err!(ffi::gcry_cipher_checktag(self.raw, mem::transmute(tag.as_ptr()),
                                                  tag.len() as libc::size_t));
        }
        Ok(())
    }

    pub fn encrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        unsafe {
            let input = (mem::transmute(input.as_ptr()), input.len());
            let output = (mem::transmute(output.as_mut_ptr()), output.len());
            return_err!(ffi::gcry_cipher_encrypt(self.raw, output.0, output.1 as libc::size_t,
                                                 input.0, input.1 as libc::size_t));
        }
        Ok(())
    }

    pub fn decrypt(&mut self, input: &[u8], output: &mut [u8]) -> Result<()> {
        unsafe {
            let input = (mem::transmute(input.as_ptr()), input.len());
            let output = (mem::transmute(output.as_mut_ptr()), output.len());
            return_err!(ffi::gcry_cipher_decrypt(self.raw, output.0, output.1 as libc::size_t,
                                                 input.0, input.1 as libc::size_t));
        }
        Ok(())
    }
}
