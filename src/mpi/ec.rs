use std::{
    ffi::CStr,
    ptr, result,
    str::{self, Utf8Error},
};

use cstr_argument::CStrArgument;
use ffi;
use libc::c_int;

use crate::{error::return_err, pkey::Algorithm, sexp::SExpression, NonNull, Result};

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

impl Curves<'_> {
    #[inline]
    pub fn all() -> Curves<'static> {
        let _ = crate::init_default();
        Curves { key: None, idx: 0 }
    }

    #[inline]
    pub fn from(key: &SExpression) -> Curves<'_> {
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

impl Iterator for Curves<'_> {
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
        if self.idx >= 0 {
            self.idx = self.idx.saturating_add(n as c_int);
        }
        self.next()
    }
}

impl ::std::iter::FusedIterator for Curves<'_> {}

#[derive(Debug)]
pub struct Context(NonNull<ffi::gcry_ctx_t>);

impl Drop for Context {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_ctx_release(self.as_raw());
        }
    }
}

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
    pub fn get_integer(&self, name: impl CStrArgument) -> Option<Integer> {
        let name = name.into_cstr();
        unsafe {
            ffi::gcry_mpi_ec_get_mpi(name.as_ref().as_ptr(), self.as_raw(), 1)
                .as_mut()
                .map(|x| Integer::from_raw(x))
        }
    }

    #[inline]
    pub fn set_integer(&mut self, name: impl CStrArgument, x: &Integer) -> Result<()> {
        let name = name.into_cstr();
        unsafe {
            return_err!(ffi::gcry_mpi_ec_set_mpi(
                name.as_ref().as_ptr(),
                x.as_raw(),
                self.as_raw()
            ));
            Ok(())
        }
    }

    #[inline]
    pub fn get_point<S: CStrArgument>(&self, name: S) -> Option<Point> {
        let name = name.into_cstr();
        unsafe {
            ffi::gcry_mpi_ec_get_point(name.as_ref().as_ptr(), self.as_raw(), 1)
                .as_mut()
                .map(|x| Point::from_raw(x))
        }
    }

    #[inline]
    pub fn set_point<S: CStrArgument>(&mut self, name: S, p: &Point) -> Result<()> {
        let name = name.into_cstr();
        unsafe {
            return_err!(ffi::gcry_mpi_ec_set_point(
                name.as_ref().as_ptr(),
                p.as_raw(),
                self.as_raw()
            ));
            Ok(())
        }
    }
}
