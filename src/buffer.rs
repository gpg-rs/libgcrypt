use std::mem;
use std::ops;
use std::slice;

use libc;
use ffi;

use Token;
use error::{Error, Result};
use rand::Level;

pub struct Buffer {
    buf: *mut u8,
    len: usize,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_free(mem::transmute(self.buf));
        }
    }
}

impl Buffer {
    pub unsafe fn from_raw(buf: *mut u8, len: usize) -> Buffer {
        Buffer {
            buf: buf,
            len: len,
        }
    }

    pub fn new(_: Token, len: usize) -> Result<Buffer> {
        unsafe {
            let buf: *mut u8 = mem::transmute(ffi::gcry_malloc(len as libc::size_t));
            if !buf.is_null() {
                Ok(Buffer::from_raw(buf, len))
            } else {
                Err(Error::last_os_error())
            }
        }
    }

    pub fn new_secure(_: Token, len: usize) -> Result<Buffer> {
        unsafe {
            let buf: *mut u8 = mem::transmute(ffi::gcry_malloc_secure(len as libc::size_t));
            if !buf.is_null() {
                Ok(Buffer::from_raw(buf, len))
            } else {
                Err(Error::last_os_error())
            }
        }
    }

    pub fn random(_: Token, len: usize, level: Level) -> Result<Buffer> {
        unsafe {
            let buf: *mut u8 = mem::transmute(ffi::gcry_random_bytes(len as libc::size_t,
                                                                     level.0));
            if !buf.is_null() {
                Ok(Buffer::from_raw(buf, len))
            } else {
                Err(Error::last_os_error())
            }
        }
    }

    pub fn random_secure(_: Token, len: usize, level: Level) -> Result<Buffer> {
        unsafe {
            let buf: *mut u8 = mem::transmute(ffi::gcry_random_bytes_secure(len as libc::size_t,
                                                                            level.0));
            if !buf.is_null() {
                Ok(Buffer::from_raw(buf, len))
            } else {
                Err(Error::last_os_error())
            }
        }
    }

    pub fn is_secure(&self) -> bool {
        unsafe {
            ffi::gcry_is_secure(mem::transmute(self.buf)) != 0
        }
    }
}

impl ops::Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl ops::DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            slice::from_raw_parts_mut(self.buf, self.len)
        }
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(self.buf, self.len)
        }
    }
}
