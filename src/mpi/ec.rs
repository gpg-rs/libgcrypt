use std::ffi::{CStr, CString};
use std::os::raw::c_int;
use std::ptr;
use std::str;

use ffi;

use {Token, Wrapper};
use error::Result;
use super::{Integer, Point};
use pkey::PK_ECC;
use sexp::SExpression;

#[derive(Copy, Clone)]
pub struct Curve {
    name: &'static CStr,
    nbits: usize,
}

impl Curve {
    pub fn name(&self) -> &'static str {
        str::from_utf8(self.name.to_bytes()).unwrap()
    }

    pub fn num_bits(&self) -> usize {
        self.nbits
    }

    pub fn parameters(&self) -> Option<SExpression> {
        unsafe {
            let result = ffi::gcry_pk_get_param(PK_ECC.raw(), self.name.as_ptr());
            if !result.is_null() {
                Some(SExpression::from_raw(result))
            } else {
                None
            }
        }
    }
}

pub struct Curves<'a> {
    key: Option<&'a SExpression>,
    idx: usize,
}

impl<'a> Curves<'a> {
    pub fn all(_: Token) -> Curves<'static> {
        Curves {
            key: None,
            idx: 0,
        }
    }

    pub fn from(key: &SExpression) -> Curves {
        Curves {
            key: Some(key),
            idx: 0,
        }
    }

    pub fn get(token: Token, name: &str) -> Option<Curve> {
        SExpression::from_bytes(token, &format!("(curve {})", name))
            .ok()
            .and_then(|s| s.curve())
    }
}

impl<'a> Iterator for Curves<'a> {
    type Item = Curve;

    fn next(&mut self) -> Option<Curve> {
        unsafe {
            let key = self.key.as_ref().map_or(ptr::null_mut(), |k| k.as_raw());
            let mut nbits = 0;
            let result = ffi::gcry_pk_get_curve(key, self.idx as c_int, &mut nbits);
            if !result.is_null() {
                self.idx += 1;
                Some(Curve {
                    name: CStr::from_ptr(result),
                    nbits: nbits as usize,
                })
            } else {
                None
            }
        }
    }

    fn nth(&mut self, n: usize) -> Option<Curve> {
        self.idx = self.idx.saturating_add(n);
        self.next()
    }
}

pub struct Context {
    raw: ffi::gcry_ctx_t,
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_ctx_release(self.raw);
        }
    }
}

unsafe impl Wrapper for Context {
    type Raw = ffi::gcry_ctx_t;

    unsafe fn from_raw(raw: ffi::gcry_ctx_t) -> Context {
        debug_assert!(!raw.is_null());
        Context { raw: raw }
    }

    fn as_raw(&self) -> ffi::gcry_ctx_t {
        self.raw
    }
}

impl Context {
    pub fn from_curve(curve: Curve) -> Result<Context> {
        let mut raw = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_mpi_ec_new(&mut raw, ptr::null_mut(), curve.name.as_ptr()));
            Ok(Context::from_raw(raw))
        }
    }

    pub fn from_params(params: &SExpression, curve: Option<Curve>) -> Result<Context> {
        let mut raw = ptr::null_mut();
        unsafe {
            let curve = curve.map_or(ptr::null(), |c| c.name.as_ptr());
            return_err!(ffi::gcry_mpi_ec_new(&mut raw, params.as_raw(), curve));
            Ok(Context::from_raw(raw))
        }
    }

    pub fn get_integer<S: Into<String>>(&self, name: S) -> Option<Integer> {
        let name = try_opt!(CString::new(name.into()).ok());
        unsafe {
            let mpi = ffi::gcry_mpi_ec_get_mpi(name.as_ptr(), self.raw, 1);
            if !mpi.is_null() {
                Some(Integer::from_raw(mpi))
            } else {
                None
            }
        }
    }

    pub fn set_integer<S: Into<String>>(&mut self, name: S, x: &Integer) -> Result<()> {
        let name = try!(CString::new(name.into()));
        unsafe {
            return_err!(ffi::gcry_mpi_ec_set_mpi(name.as_ptr(), x.as_raw(), self.raw));
            Ok(())
        }
    }

    pub fn get_point<S: Into<String>>(&self, name: S) -> Option<Point> {
        let name = try_opt!(CString::new(name.into()).ok());
        unsafe {
            let point = ffi::gcry_mpi_ec_get_point(name.as_ptr(), self.raw, 1);
            if !point.is_null() {
                Some(Point::from_raw(point))
            } else {
                None
            }
        }
    }

    pub fn set_point<S: Into<String>>(&mut self, name: S, p: &Point) -> Result<()> {
        let name = try!(CString::new(name.into()));
        unsafe {
            return_err!(ffi::gcry_mpi_ec_set_point(name.as_ptr(), p.as_raw(), self.raw));
            Ok(())
        }
    }
}
