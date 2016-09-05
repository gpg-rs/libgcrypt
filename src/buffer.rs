use std::ops;
use std::ptr;
use std::slice;
use std::result;
use std::str;

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
            ffi::gcry_free(self.buf as *mut _);
        }
    }
}

impl Buffer {
    pub unsafe fn from_raw(buf: *mut u8, len: usize) -> Buffer {
        debug_assert!(!buf.is_null());
        Buffer {
            buf: buf,
            len: len,
        }
    }

    pub fn new(_: Token, len: usize) -> Result<Buffer> {
        unsafe {
            ffi::gcry_malloc(len).as_mut().map(|x| {
                Buffer::from_raw(x as *mut _ as *mut _, len)
            }).ok_or_else(|| Error::last_os_error())
        }
    }

    pub fn new_secure(_: Token, len: usize) -> Result<Buffer> {
        unsafe {
            ffi::gcry_malloc_secure(len).as_mut().map(|x| {
                Buffer::from_raw(x as *mut _ as *mut _, len)
            }).ok_or_else(|| Error::last_os_error())
        }
    }

    pub fn try_clone(&self) -> Result<Buffer> {
        let token = ::Token(());
        let result = if self.is_secure() {
            try!(Buffer::new_secure(token, self.len))
        } else {
            try!(Buffer::new(token, self.len))
        };
        unsafe {
            ptr::copy_nonoverlapping(self.buf, result.buf, self.len);
        }
        Ok(result)
    }

    pub fn random(_: Token, len: usize, level: Level) -> Result<Buffer> {
        unsafe {
            ffi::gcry_random_bytes(len, level.raw()).as_mut().map(|x| {
                Buffer::from_raw(x as *mut _ as *mut _, len)
            }).ok_or_else(|| Error::last_os_error())
        }
    }

    pub fn random_secure(_: Token, len: usize, level: Level) -> Result<Buffer> {
        unsafe {
            ffi::gcry_random_bytes_secure(len, level.raw()).as_mut().map(|x| {
                Buffer::from_raw(x as *mut _ as *mut _, len)
            }).ok_or_else(|| Error::last_os_error())
        }
    }

    pub fn is_secure(&self) -> bool {
        unsafe { ffi::gcry_is_secure(self.buf as *const _) != 0 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.buf, self.len) }
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.buf, self.len) }
    }

    pub fn to_str(&self) -> result::Result<&str, str::Utf8Error> {
        str::from_utf8(self.as_bytes())
    }
}

impl ops::Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl ops::DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}
