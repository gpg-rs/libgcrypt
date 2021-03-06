use std::{
    convert::TryFrom,
    fmt, ptr, result, slice,
    str::{self, FromStr, Utf8Error},
};

use ffi;
use libc::c_int;

use crate::{
    error::return_err,
    mpi::{integer::Format as IntegerFormat, Integer},
    Error, NonNull, Result,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Format {
    Default = ffi::GCRYSEXP_FMT_DEFAULT as isize,
    Canonical = ffi::GCRYSEXP_FMT_CANON as isize,
    Base64 = ffi::GCRYSEXP_FMT_BASE64 as isize,
    Advanced = ffi::GCRYSEXP_FMT_ADVANCED as isize,
}

pub struct SExpression(NonNull<ffi::gcry_sexp_t>);

impl Drop for SExpression {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_sexp_release(self.as_raw());
        }
    }
}

impl SExpression {
    impl_wrapper!(SExpression: ffi::gcry_sexp_t);

    #[inline]
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<SExpression> {
        let _ = crate::init_default();
        let bytes = bytes.as_ref();
        unsafe {
            let mut result: ffi::gcry_sexp_t = ptr::null_mut();
            return_err!(ffi::gcry_sexp_sscan(
                &mut result,
                ptr::null_mut(),
                bytes.as_ptr().cast(),
                bytes.len()
            ));
            Ok(SExpression::from_raw(result))
        }
    }

    #[inline]
    pub fn to_bytes(&self, format: Format) -> Vec<u8> {
        let mut buffer = vec![0; self.len_encoded(format)];
        self.encode(format, &mut buffer);
        buffer.pop();
        buffer
    }

    #[inline]
    pub fn len_encoded(&self, format: Format) -> usize {
        unsafe { ffi::gcry_sexp_sprint(self.as_raw(), format as c_int, ptr::null_mut(), 0) }
    }

    #[inline]
    pub fn encode(&self, format: Format, buf: &mut [u8]) -> Option<usize> {
        unsafe {
            match ffi::gcry_sexp_sprint(
                self.as_raw(),
                format as c_int,
                buf.as_mut_ptr().cast(),
                buf.len(),
            ) {
                0 => None,
                x => Some(x),
            }
        }
    }

    #[inline]
    pub fn elements(&self) -> Elements<'_> {
        unsafe {
            Elements {
                sexp: self,
                first: 0,
                last: ffi::gcry_sexp_length(self.as_raw()),
            }
        }
    }

    #[inline]
    pub fn head(&self) -> Option<SExpression> {
        unsafe {
            ffi::gcry_sexp_car(self.as_raw())
                .as_mut()
                .map(|x| SExpression::from_raw(x))
        }
    }

    #[inline]
    pub fn tail(&self) -> Option<SExpression> {
        unsafe {
            ffi::gcry_sexp_cdr(self.as_raw())
                .as_mut()
                .map(|x| SExpression::from_raw(x))
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn len(&self) -> usize {
        unsafe { ffi::gcry_sexp_length(self.as_raw()) as usize }
    }

    #[inline]
    pub fn find_token(&self, token: impl AsRef<[u8]>) -> Option<SExpression> {
        let token = token.as_ref();
        unsafe {
            ffi::gcry_sexp_find_token(self.as_raw(), token.as_ptr().cast(), token.len())
                .as_mut()
                .map(|x| SExpression::from_raw(x))
        }
    }

    #[inline]
    pub fn get(&self, idx: u32) -> Option<SExpression> {
        unsafe {
            ffi::gcry_sexp_nth(self.as_raw(), idx as c_int)
                .as_mut()
                .map(|x| SExpression::from_raw(x))
        }
    }

    #[inline]
    pub fn get_bytes(&self, idx: u32) -> Option<&[u8]> {
        unsafe {
            let mut len = 0;
            ffi::gcry_sexp_nth_data(self.as_raw(), idx as c_int, &mut len)
                .as_ref()
                .map(|x| slice::from_raw_parts(x as *const _ as *const _, len))
        }
    }

    #[inline]
    pub fn get_str(&self, idx: u32) -> result::Result<&str, Option<Utf8Error>> {
        self.get_bytes(idx)
            .map_or(Err(None), |s| str::from_utf8(s).map_err(Some))
    }

    #[inline]
    pub fn get_integer(&self, idx: u32, fmt: IntegerFormat) -> Option<Integer> {
        unsafe {
            ffi::gcry_sexp_nth_mpi(self.as_raw(), idx as c_int, fmt as c_int)
                .as_mut()
                .map(|x| Integer::from_raw(x))
        }
    }
}

impl TryFrom<&[u8]> for SExpression {
    type Error = Error;

    #[inline]
    fn try_from(b: &[u8]) -> Result<Self> {
        SExpression::from_bytes(b)
    }
}

impl FromStr for SExpression {
    type Err = Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self> {
        SExpression::from_bytes(s)
    }
}

impl fmt::Debug for SExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use std::{ascii, fmt::Write};

        f.write_str("SExpression(\"")?;
        for b in self
            .to_bytes(Format::Advanced)
            .into_iter()
            .flat_map(|b| ascii::escape_default(b))
        {
            f.write_char(b as char)?;
        }
        f.write_str("\")")
    }
}

impl<'a> IntoIterator for &'a SExpression {
    type Item = SExpression;
    type IntoIter = Elements<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.elements()
    }
}

#[derive(Debug)]
pub struct Elements<'a> {
    sexp: &'a SExpression,
    first: c_int,
    last: c_int,
}

impl Iterator for Elements<'_> {
    type Item = SExpression;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.first < self.last {
            let elem = unsafe {
                SExpression::from_raw(ffi::gcry_sexp_nth(self.sexp.as_raw(), self.first))
            };
            self.first += 1;
            Some(elem)
        } else {
            None
        }
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.first = if (n as u64) < ((self.last - self.first) as u64) {
            self.first + (n as c_int)
        } else {
            self.last
        };
        self.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = (self.last - self.first) as usize;
        (size, Some(size))
    }
}

impl DoubleEndedIterator for Elements<'_> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.first < self.last {
            self.last -= 1;
            unsafe {
                Some(SExpression::from_raw(ffi::gcry_sexp_nth(
                    self.sexp.as_raw(),
                    self.last,
                )))
            }
        } else {
            None
        }
    }
}

impl ExactSizeIterator for Elements<'_> {}
impl ::std::iter::FusedIterator for Elements<'_> {}
