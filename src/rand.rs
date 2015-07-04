use std::mem;

use libc;
use ffi;

pub const WEAK_RANDOM: Level = Level(ffi::GCRY_WEAK_RANDOM);
pub const STRONG_RANDOM: Level = Level(ffi::GCRY_STRONG_RANDOM);
pub const VERY_STRONG_RANDOM: Level = Level(ffi::GCRY_VERY_STRONG_RANDOM);

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Level(pub ffi::gcry_random_level_t);

pub trait Random {
    fn make_nonce(&mut self);
    fn randomize(&mut self, level: Level);
}

impl Random for [u8] {
    fn make_nonce(&mut self) {
        unsafe {
            let buffer = (mem::transmute(self.as_mut_ptr()), self.len());
            ffi::gcry_create_nonce(buffer.0, buffer.1 as libc::size_t);
        }
    }

    fn randomize(&mut self, level: Level) {
        unsafe {
            let buffer = (mem::transmute(self.as_mut_ptr()), self.len());
            ffi::gcry_randomize(buffer.0, buffer.1 as libc::size_t, level.0);
        }
    }
}

impl<'a> Random for &'a mut [u8] {
    fn make_nonce(&mut self) {
        unsafe {
            let buffer = (mem::transmute(self.as_mut_ptr()), self.len());
            ffi::gcry_create_nonce(buffer.0, buffer.1 as libc::size_t);
        }
    }

    fn randomize(&mut self, level: Level) {
        unsafe {
            let buffer = (mem::transmute(self.as_mut_ptr()), self.len());
            ffi::gcry_randomize(buffer.0, buffer.1 as libc::size_t, level.0);
        }
    }
}
