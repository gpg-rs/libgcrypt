use std::os::raw::c_uint;
use std::ptr;

use ffi;

use {Wrapper, Token};
use super::{Integer, Context};

#[derive(Debug)]
pub struct Point {
    raw: ffi::gcry_mpi_point_t,
}

impl Drop for Point {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_mpi_point_release(self.raw);
        }
    }
}

impl Clone for Point {
    fn clone(&self) -> Point {
        let (x, y, z) = self.to_coords();
        unsafe {
            Point::from_raw(ffi::gcry_mpi_point_snatch_set(ptr::null_mut(),
                                                           x.into_raw(),
                                                           y.into_raw(),
                                                           z.into_raw()))
        }
    }

    fn clone_from(&mut self, source: &Point) {
        let (x, y, z) = source.to_coords();
        unsafe {
            ffi::gcry_mpi_point_snatch_set(self.raw, x.into_raw(), y.into_raw(), z.into_raw());
        }
    }
}

unsafe impl Wrapper for Point {
    type Raw = ffi::gcry_mpi_point_t;

    unsafe fn from_raw(raw: ffi::gcry_mpi_point_t) -> Point {
        debug_assert!(!raw.is_null());
        Point { raw: raw }
    }

    fn as_raw(&self) -> ffi::gcry_mpi_point_t {
        self.raw
    }
}

impl Point {
    pub fn zero(token: Token) -> Point {
        Point::new(token, 0)
    }

    pub fn new(_: Token, nbits: usize) -> Point {
        unsafe { Point::from_raw(ffi::gcry_mpi_point_new(nbits as c_uint)) }
    }

    pub fn from(x: Option<Integer>, y: Option<Integer>, z: Option<Integer>) -> Point {
        unsafe {
            let x = x.map_or(ptr::null_mut(), |v| v.into_raw());
            let y = y.map_or(ptr::null_mut(), |v| v.into_raw());
            let z = z.map_or(ptr::null_mut(), |v| v.into_raw());
            Point::from_raw(ffi::gcry_mpi_point_snatch_set(ptr::null_mut(), x, y, z))
        }
    }

    pub fn set(&mut self, x: Option<Integer>, y: Option<Integer>, z: Option<Integer>) {
        unsafe {
            let x = x.map_or(ptr::null_mut(), |v| v.into_raw());
            let y = y.map_or(ptr::null_mut(), |v| v.into_raw());
            let z = z.map_or(ptr::null_mut(), |v| v.into_raw());
            ffi::gcry_mpi_point_snatch_set(self.raw, x, y, z);
        }
    }

    pub fn to_coords(&self) -> (Integer, Integer, Integer) {
        let token = ::get_token().unwrap();
        let x = Integer::zero(token);
        let y = Integer::zero(token);
        let z = Integer::zero(token);
        unsafe {
            ffi::gcry_mpi_point_get(x.as_raw(), y.as_raw(), z.as_raw(), self.raw);
        }
        (x, y, z)
    }

    pub fn into_coords(self) -> (Integer, Integer, Integer) {
        let token = ::get_token().unwrap();
        let x = Integer::zero(token);
        let y = Integer::zero(token);
        let z = Integer::zero(token);
        unsafe {
            ffi::gcry_mpi_point_snatch_get(x.as_raw(), y.as_raw(), z.as_raw(), self.into_raw());
        }
        (x, y, z)
    }

    pub fn get_affine(&self, ctx: &Context) -> Option<(Integer, Integer)> {
        let token = ::get_token().unwrap();
        let x = Integer::zero(token);
        let y = Integer::zero(token);
        let result =
            unsafe { ffi::gcry_mpi_ec_get_affine(x.as_raw(), y.as_raw(), self.raw, ctx.as_raw()) };
        if result == 0 { Some((x, y)) } else { None }
    }

    pub fn on_curve(&self, ctx: &Context) -> bool {
        unsafe { ffi::gcry_mpi_ec_curve_point(self.raw, ctx.as_raw()) != 0 }
    }

    pub fn add(self, other: &Point, ctx: &Context) -> Point {
        unsafe {
            ffi::gcry_mpi_ec_add(self.raw, self.raw, other.raw, ctx.as_raw());
        }
        self
    }

    pub fn mul(self, n: &Integer, ctx: &Context) -> Point {
        unsafe {
            ffi::gcry_mpi_ec_mul(self.raw, n.as_raw(), self.raw, ctx.as_raw());
        }
        self
    }
}
