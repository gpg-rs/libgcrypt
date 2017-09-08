use std::ops;
use std::ptr;
use std::slice;
use std::result;
use std::str;

use ffi;

use {Error, NonZero, Result};
use rand::Level;

#[derive(Debug)]
pub struct Buffer {
    buf: NonZero<*mut u8>,
    len: usize,
}

impl Drop for Buffer {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_free(self.buf.get() as *mut _);
        }
    }
}

impl Buffer {
    #[inline]
    pub unsafe fn from_raw(buf: *mut u8, len: usize) -> Buffer {
        Buffer {
            buf: NonZero::new(buf).unwrap(),
            len: len,
        }
    }

    #[inline]
    pub fn new(len: usize) -> Result<Buffer> {
        let _ = ::get_token();
        unsafe {
            ffi::gcry_malloc(len)
                .as_mut()
                .map(|x| Buffer::from_raw(x as *mut _ as *mut _, len))
                .ok_or_else(Error::last_os_error)
        }
    }

    #[inline]
    pub fn new_secure(len: usize) -> Result<Buffer> {
        let _ = ::get_token();
        unsafe {
            ffi::gcry_malloc_secure(len)
                .as_mut()
                .map(|x| Buffer::from_raw(x as *mut _ as *mut _, len))
                .ok_or_else(Error::last_os_error)
        }
    }

    #[inline]
    pub fn try_clone(&self) -> Result<Buffer> {
        let result = if self.is_secure() {
            try!(Buffer::new_secure(self.len))
        } else {
            try!(Buffer::new(self.len))
        };
        unsafe {
            ptr::copy_nonoverlapping(self.buf.get(), result.buf.get(), self.len);
        }
        Ok(result)
    }

    #[inline]
    pub fn random(len: usize, level: Level) -> Result<Buffer> {
        let _ = ::get_token();
        unsafe {
            ffi::gcry_random_bytes(len, level.raw())
                .as_mut()
                .map(|x| Buffer::from_raw(x as *mut _ as *mut _, len))
                .ok_or_else(Error::last_os_error)
        }
    }

    #[inline]
    pub fn random_secure(len: usize, level: Level) -> Result<Buffer> {
        let _ = ::get_token();
        unsafe {
            ffi::gcry_random_bytes_secure(len, level.raw())
                .as_mut()
                .map(|x| Buffer::from_raw(x as *mut _ as *mut _, len))
                .ok_or_else(Error::last_os_error)
        }
    }

    #[inline]
    pub fn is_secure(&self) -> bool {
        unsafe { ffi::gcry_is_secure(self.buf.get() as *const _) != 0 }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.buf.get(), self.len) }
    }

    #[inline]
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.buf.get(), self.len) }
    }

    #[inline]
    pub fn to_str(&self) -> result::Result<&str, str::Utf8Error> {
        str::from_utf8(self.as_bytes())
    }
}

impl ops::Deref for Buffer {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl ops::DerefMut for Buffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}

impl AsRef<[u8]> for Buffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsMut<[u8]> for Buffer {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_bytes()
    }
}
