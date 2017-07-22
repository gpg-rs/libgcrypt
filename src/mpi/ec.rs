use std::ffi::CStr;
#[cfg(feature = "v1_6_0")]
use std::ffi::CString;
use std::ptr;
use std::result;
use std::str::{self, Utf8Error};

use ffi;
use libc::c_int;

#[cfg(feature = "v1_6_0")]
use {NonZero, Result};
use pkey::Algorithm;
use sexp::SExpression;

#[cfg(feature = "v1_6_0")]
use super::{Integer, Point};

#[derive(Debug, Copy, Clone)]
pub struct Curve {
    name: &'static CStr,
    nbits: usize,
}

impl Curve {
    #[inline]
    pub fn name(&self) -> result::Result<&'static str, Utf8Error> {
        self.name.to_str()
    }

    #[inline]
    pub fn name_raw(&self) -> &'static CStr {
        self.name
    }

    #[inline]
    pub fn num_bits(&self) -> usize {
        self.nbits
    }

    #[inline]
    pub fn parameters(&self) -> Option<SExpression> {
        unsafe {
            ffi::gcry_pk_get_param(Algorithm::Ecc.raw(), self.name.as_ptr())
                .as_mut()
                .map(|x| SExpression::from_raw(x))
        }
    }
}

#[derive(Debug)]
pub struct Curves<'a> {
    key: Option<&'a SExpression>,
    idx: c_int,
}

impl<'a> Curves<'a> {
    #[inline]
    pub fn all() -> Curves<'static> {
        let _ = ::get_token();
        Curves { key: None, idx: 0 }
    }

    #[inline]
    pub fn from(key: &SExpression) -> Curves {
        Curves {
            key: Some(key),
            idx: 0,
        }
    }

    #[inline]
    pub fn get(name: &str) -> Option<Curve> {
        SExpression::from_bytes(format!("(curve {})", name))
            .ok()
            .and_then(|s| Curves::from(&s).next())
    }
}

impl<'a> Iterator for Curves<'a> {
    type Item = Curve;

    #[inline]
    fn next(&mut self) -> Option<Curve> {
        let key = self.key.as_ref().map_or(ptr::null_mut(), |k| k.as_raw());
        unsafe {
            let mut nbits = 0;
            ffi::gcry_pk_get_curve(key, self.idx, &mut nbits)
                .as_ref()
                .map(|x| {
                    self.idx = self.idx.checked_add(1).unwrap_or(-1);
                    Curve {
                        name: CStr::from_ptr(x),
                        nbits: nbits as usize,
                    }
                })
        }
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Curve> {
        self.idx = self.idx.saturating_add(n as c_int);
        self.next()
    }
}

#[cfg(feature = "v1_6_0")]
#[derive(Debug)]
pub struct Context(NonZero<ffi::gcry_ctx_t>);

#[cfg(feature = "v1_6_0")]
impl Drop for Context {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_ctx_release(self.as_raw());
        }
    }
}

#[cfg(feature = "v1_6_0")]
impl Context {
    impl_wrapper!(Context: ffi::gcry_ctx_t);

    #[inline]
    pub fn from_curve(curve: Curve) -> Result<Context> {
        let mut raw = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_mpi_ec_new(
                &mut raw,
                ptr::null_mut(),
                curve.name.as_ptr()
            ));
            Ok(Context::from_raw(raw))
        }
    }

    #[inline]
    pub fn from_params(params: &SExpression, curve: Option<Curve>) -> Result<Context> {
        let mut raw = ptr::null_mut();
        unsafe {
            let curve = curve.map_or(ptr::null(), |c| c.name.as_ptr());
            return_err!(ffi::gcry_mpi_ec_new(&mut raw, params.as_raw(), curve));
            Ok(Context::from_raw(raw))
        }
    }

    #[inline]
    pub fn get_integer<S: Into<String>>(&self, name: S) -> Option<Integer> {
        let name = try_opt!(CString::new(name.into()).ok());
        unsafe {
            ffi::gcry_mpi_ec_get_mpi(name.as_ptr(), self.as_raw(), 1)
                .as_mut()
                .map(|x| Integer::from_raw(x))
        }
    }

    #[inline]
    pub fn set_integer<S: Into<String>>(&mut self, name: S, x: &Integer) -> Result<()> {
        let name = try!(CString::new(name.into()));
        unsafe {
            return_err!(ffi::gcry_mpi_ec_set_mpi(
                name.as_ptr(),
                x.as_raw(),
                self.as_raw()
            ));
            Ok(())
        }
    }

    #[inline]
    pub fn get_point<S: Into<String>>(&self, name: S) -> Option<Point> {
        let name = try_opt!(CString::new(name.into()).ok());
        unsafe {
            ffi::gcry_mpi_ec_get_point(name.as_ptr(), self.as_raw(), 1)
                .as_mut()
                .map(|x| Point::from_raw(x))
        }
    }

    #[inline]
    pub fn set_point<S: Into<String>>(&mut self, name: S, p: &Point) -> Result<()> {
        let name = try!(CString::new(name.into()));
        unsafe {
            return_err!(ffi::gcry_mpi_ec_set_point(
                name.as_ptr(),
                p.as_raw(),
                self.as_raw()
            ));
            Ok(())
        }
    }
}
