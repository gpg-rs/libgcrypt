use std::ops;
use std::result;
use std::slice;
use std::str;

use ffi;

use rand::Level;
use {Error, NonNull, Result};

#[derive(Debug)]
pub struct Buffer {
    buf: NonNull<*mut u8>,
    len: usize,
}

impl Drop for Buffer {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_free(self.buf.as_ptr() as *mut _);
        }
    }
}

impl Buffer {
    #[inline]
    pub unsafe fn from_raw(buf: *mut u8, len: usize) -> Buffer {
        Buffer {
            buf: NonNull::<*mut u8>::new(buf).unwrap(),
            len: len,
        }
    }

    #[inline]
    pub fn new(len: usize) -> Result<Buffer> {
        let _ = ::init_default();
        unsafe {
            ffi::gcry_malloc(len)
                .as_mut()
                .map(|x| Buffer::from_raw(x as *mut _ as *mut _, len))
                .ok_or_else(Error::last_os_error)
        }
    }

    #[inline]
    pub fn new_secure(len: usize) -> Result<Buffer> {
        let _ = ::init_default();
        unsafe {
            ffi::gcry_malloc_secure(len)
                .as_mut()
                .map(|x| Buffer::from_raw(x as *mut _ as *mut _, len))
                .ok_or_else(Error::last_os_error)
        }
    }

    #[inline]
    pub fn try_clone(&self) -> Result<Buffer> {
        let mut result = if self.is_secure() {
            Buffer::new_secure(self.len)?
        } else {
            Buffer::new(self.len)?
        };
        result.copy_from_slice(self);
        Ok(result)
    }

    #[inline]
    pub fn random(len: usize, level: Level) -> Result<Buffer> {
        let _ = ::init_default();
        unsafe {
            ffi::gcry_random_bytes(len, level.raw())
                .as_mut()
                .map(|x| Buffer::from_raw(x as *mut _ as *mut _, len))
                .ok_or_else(Error::last_os_error)
        }
    }

    #[inline]
    pub fn random_secure(len: usize, level: Level) -> Result<Buffer> {
        let _ = ::init_default();
        unsafe {
            ffi::gcry_random_bytes_secure(len, level.raw())
                .as_mut()
                .map(|x| Buffer::from_raw(x as *mut _ as *mut _, len))
                .ok_or_else(Error::last_os_error)
        }
    }

    #[inline]
    pub fn is_secure(&self) -> bool {
        unsafe { ffi::gcry_is_secure(self.buf.as_ptr() as *const _) != 0 }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.buf.as_ptr(), self.len) }
    }

    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.buf.as_ptr(), self.len) }
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
        self.as_bytes_mut()
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
        self.as_bytes_mut()
    }
}
