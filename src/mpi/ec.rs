use std::ffi::{CStr, CString};
use std::ptr;
use std::str;

use ffi;
use libc::c_int;

use Token;
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
            ffi::gcry_pk_get_param(PK_ECC.raw(), self.name.as_ptr())
                .as_mut()
                .map(|x| SExpression::from_raw(x))
        }
    }
}

pub struct Curves<'a> {
    key: Option<&'a SExpression>,
    idx: c_int,
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
        SExpression::from_bytes(token, format!("(curve {})", name)).ok().and_then(|s| s.curve())
    }
}

impl<'a> Iterator for Curves<'a> {
    type Item = Curve;

    fn next(&mut self) -> Option<Curve> {
        let key = self.key.as_ref().map_or(ptr::null_mut(), |k| k.as_raw());
        unsafe {
            let mut nbits = 0;
            ffi::gcry_pk_get_curve(key, self.idx, &mut nbits).as_ref().map(|x| {
                self.idx = self.idx.checked_add(1).unwrap_or(-1);
                Curve {
                    name: CStr::from_ptr(x),
                    nbits: nbits as usize,
                }
            })
        }
    }

    fn nth(&mut self, n: usize) -> Option<Curve> {
        self.idx = self.idx.saturating_add(n as c_int);
        self.next()
    }
}

pub struct Context(ffi::gcry_ctx_t);

impl_wrapper!(Context: ffi::gcry_ctx_t);

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_ctx_release(self.0);
        }
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
            ffi::gcry_mpi_ec_get_mpi(name.as_ptr(), self.0, 1)
                .as_mut()
                .map(|x| Integer::from_raw(x))
        }
    }

    pub fn set_integer<S: Into<String>>(&mut self, name: S, x: &Integer) -> Result<()> {
        let name = try!(CString::new(name.into()));
        unsafe {
            return_err!(ffi::gcry_mpi_ec_set_mpi(name.as_ptr(), x.as_raw(), self.0));
            Ok(())
        }
    }

    pub fn get_point<S: Into<String>>(&self, name: S) -> Option<Point> {
        let name = try_opt!(CString::new(name.into()).ok());
        unsafe {
            ffi::gcry_mpi_ec_get_point(name.as_ptr(), self.0, 1)
                .as_mut()
                .map(|x| Point::from_raw(x))
        }
    }

    pub fn set_point<S: Into<String>>(&mut self, name: S, p: &Point) -> Result<()> {
        let name = try!(CString::new(name.into()));
        unsafe {
            return_err!(ffi::gcry_mpi_ec_set_point(name.as_ptr(), p.as_raw(), self.0));
            Ok(())
        }
    }
}
