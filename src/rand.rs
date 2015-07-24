use libc;
use ffi;

use Token;

enum_wrapper! {
    pub enum Level: ffi::gcry_random_level_t {
        WEAK_RANDOM = ffi::GCRY_WEAK_RANDOM,
        STRONG_RANDOM = ffi::GCRY_STRONG_RANDOM,
        VERY_STRONG_RANDOM = ffi::GCRY_VERY_STRONG_RANDOM,
    }
}

pub trait Random {
    fn make_nonce(&mut self, _: Token);
    fn randomize(&mut self, _: Token, level: Level);
}

impl Random for [u8] {
    fn make_nonce(&mut self, _: Token) {
        unsafe {
            let buffer = (self.as_mut_ptr() as *mut _, self.len());
            ffi::gcry_create_nonce(buffer.0, buffer.1 as libc::size_t);
        }
    }

    fn randomize(&mut self, _: Token, level: Level) {
        unsafe {
            let buffer = (self.as_mut_ptr() as *mut _, self.len());
            ffi::gcry_randomize(buffer.0, buffer.1 as libc::size_t, level.0);
        }
    }
}

impl<'a> Random for &'a mut [u8] {
    fn make_nonce(&mut self, _: Token) {
        unsafe {
            let buffer = (self.as_mut_ptr() as *mut _, self.len());
            ffi::gcry_create_nonce(buffer.0, buffer.1 as libc::size_t);
        }
    }

    fn randomize(&mut self, _: Token, level: Level) {
        unsafe {
            let buffer = (self.as_mut_ptr() as *mut _, self.len());
            ffi::gcry_randomize(buffer.0, buffer.1 as libc::size_t, level.0);
        }
    }
}
