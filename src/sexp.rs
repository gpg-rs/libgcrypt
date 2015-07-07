use std::ffi::CString;
use std::ptr;
use std::slice;
use std::str;

use libc;
use ffi;

use Wrapper;
use error::{Error, Result};
use mpi::Integer;
use mpi::integer::Format as IntegerFormat;

pub struct SExpression {
    raw: ffi::gcry_sexp_t,
}

impl Drop for SExpression {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_sexp_release(self.raw);
        }
    }
}

unsafe impl Wrapper for SExpression {
    type Raw = ffi::gcry_sexp_t;

    unsafe fn from_raw(raw: ffi::gcry_sexp_t) -> SExpression {
        debug_assert!(!raw.is_null());
        SExpression { raw: raw }
    }

    fn as_raw(&self) -> ffi::gcry_sexp_t {
        self.raw
    }
}

impl SExpression {
    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<SExpression> {
        let bytes = bytes.as_ref();
        unsafe {
            let mut result: ffi::gcry_sexp_t = ptr::null_mut();
            return_err!(ffi::gcry_sexp_new(&mut result, bytes.as_ptr() as *const _,
                                           bytes.len() as libc::size_t, 1));
            Ok(SExpression::from_raw(result))
        }
    }

    pub fn elements(&self) -> Elements {
        Elements {
            sexp: self,
            first: 0,
            last: self.len(),
        }
    }

    pub fn head(&self) -> Option<SExpression> {
        unsafe {
            let result = ffi::gcry_sexp_car(self.raw);
            if !result.is_null() {
                Some(SExpression::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn tail(&self) -> Option<SExpression> {
        unsafe {
            let result = ffi::gcry_sexp_cdr(self.raw);
            if !result.is_null() {
                Some(SExpression::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn len(&self) -> usize {
        unsafe {
            ffi::gcry_sexp_length(self.raw) as usize
        }
    }

    pub fn get(&self, idx: usize) -> Option<SExpression> {
        unsafe {
            let result = ffi::gcry_sexp_nth(self.raw, idx as libc::c_int);
            if !result.is_null() {
                Some(SExpression::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn get_bytes(&self, idx: usize) -> Option<&[u8]> {
        unsafe {
            let mut datalen: libc::size_t = 0;
            let result = ffi::gcry_sexp_nth_data(self.raw, idx as libc::c_int,
                                                 &mut datalen);
            if !result.is_null() {
                Some(slice::from_raw_parts(result as *const _, datalen as usize))
            } else {
                None
            }
        }
    }

    pub fn get_str(&self, idx: usize) -> Option<&str> {
        self.get_bytes(idx).and_then(|b| str::from_utf8(b).ok())
    }

    pub fn get_integer(&self, idx: usize, fmt: IntegerFormat) -> Option<Integer> {
        unsafe {
            let result = ffi::gcry_sexp_nth_mpi(self.raw, idx as libc::c_int,
                                                fmt as libc::c_int);
            if !result.is_null() {
                Some(Integer::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn find_token<S: Into<String>>(&self, token: S) -> Option<SExpression> {
        let token = try_opt!(CString::new(token.into()).ok());
        unsafe {
            let result = ffi::gcry_sexp_find_token(self.raw, token.as_ptr(), 0);
            if !result.is_null() {
                Some(SExpression::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn find_raw_token<B: AsRef<[u8]>>(&self, token: B) -> Option<SExpression> {
        let token = token.as_ref();
        unsafe {
            let result = ffi::gcry_sexp_find_token(self.raw, token.as_ptr() as *const _,
                                                   token.len() as libc::size_t);
            if !result.is_null() {
                Some(SExpression::from_raw(result))
            } else {
                None
            }
        }
    }
}

impl str::FromStr for SExpression {
    type Err = Error;

    fn from_str(s: &str) -> Result<SExpression> {
        unsafe {
            let mut result: ffi::gcry_sexp_t = ptr::null_mut();
            return_err!(ffi::gcry_sexp_sscan(&mut result, ptr::null_mut(), s.as_ptr() as *const _,
                                             s.len() as libc::size_t));
            Ok(SExpression::from_raw(result))
        }
    }
}

impl<'a> IntoIterator for &'a SExpression {
    type Item = SExpression;
    type IntoIter = Elements<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements()
    }
}

pub struct Elements<'a> {
    sexp: &'a SExpression,
    first: usize,
    last: usize,
}

impl<'a> Iterator for Elements<'a> {
    type Item = SExpression;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first < self.last {
            let elem = unsafe {
                SExpression::from_raw(ffi::gcry_sexp_nth(self.sexp.as_raw(),
                                                         self.first as libc::c_int))
            };
            self.first += 1;
            Some(elem)
        } else {
            None
        }
    }

    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.first = self.first.saturating_add(n);
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.last - self.first;
        (size, Some(size))
    }
}
impl<'a> DoubleEndedIterator for Elements<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.first < self.last {
            self.last -= 1;
            unsafe {
                Some(SExpression::from_raw(ffi::gcry_sexp_nth(self.sexp.as_raw(),
                                                              self.first as libc::c_int)))
            }
        } else {
            None
        }
    }
}
impl<'a> ExactSizeIterator for Elements<'a> {}
