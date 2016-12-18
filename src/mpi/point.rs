use std::ptr;

use ffi;

use NonZero;
use super::{Context, Integer};

#[derive(Debug)]
pub struct Point(NonZero<ffi::gcry_mpi_point_t>);

impl Drop for Point {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_mpi_point_release(self.as_raw());
        }
    }
}

impl Clone for Point {
    #[inline]
    fn clone(&self) -> Point {
        let (x, y, z) = self.to_coords();
        unsafe {
            Point::from_raw(ffi::gcry_mpi_point_snatch_set(ptr::null_mut(),
                                                           x.into_raw(),
                                                           y.into_raw(),
                                                           z.into_raw()))
        }
    }

    #[inline]
    fn clone_from(&mut self, source: &Point) {
        let (x, y, z) = source.to_coords();
        unsafe {
            ffi::gcry_mpi_point_snatch_set(self.as_raw(), x.into_raw(), y.into_raw(), z.into_raw());
        }
    }
}

impl Point {
    impl_wrapper!(Point: ffi::gcry_mpi_point_t);

    #[inline]
    pub fn zero() -> Point {
        Point::new(0)
    }

    #[inline]
    pub fn new(nbits: u32) -> Point {
        let _ = ::get_token();
        unsafe { Point::from_raw(ffi::gcry_mpi_point_new(nbits.into())) }
    }

    #[inline]
    pub fn from(x: Option<Integer>, y: Option<Integer>, z: Option<Integer>) -> Point {
        let _ = ::get_token();
        unsafe {
            let x = x.map_or(ptr::null_mut(), |v| v.into_raw());
            let y = y.map_or(ptr::null_mut(), |v| v.into_raw());
            let z = z.map_or(ptr::null_mut(), |v| v.into_raw());
            Point::from_raw(ffi::gcry_mpi_point_snatch_set(ptr::null_mut(), x, y, z))
        }
    }

    #[inline]
    pub fn set(&mut self, x: Option<Integer>, y: Option<Integer>, z: Option<Integer>) {
        unsafe {
            let x = x.map_or(ptr::null_mut(), |v| v.into_raw());
            let y = y.map_or(ptr::null_mut(), |v| v.into_raw());
            let z = z.map_or(ptr::null_mut(), |v| v.into_raw());
            ffi::gcry_mpi_point_snatch_set(self.as_raw(), x, y, z);
        }
    }

    #[inline]
    pub fn to_coords(&self) -> (Integer, Integer, Integer) {
        let x = Integer::zero();
        let y = Integer::zero();
        let z = Integer::zero();
        unsafe {
            ffi::gcry_mpi_point_get(x.as_raw(), y.as_raw(), z.as_raw(), self.as_raw());
        }
        (x, y, z)
    }

    #[inline]
    pub fn into_coords(self) -> (Integer, Integer, Integer) {
        let x = Integer::zero();
        let y = Integer::zero();
        let z = Integer::zero();
        unsafe {
            ffi::gcry_mpi_point_snatch_get(x.as_raw(), y.as_raw(), z.as_raw(), self.into_raw());
        }
        (x, y, z)
    }

    #[inline]
    pub fn get_affine(&self, ctx: &Context) -> Option<(Integer, Integer)> {
        let x = Integer::zero();
        let y = Integer::zero();
        let result =
            unsafe { ffi::gcry_mpi_ec_get_affine(x.as_raw(), y.as_raw(), self.as_raw(), ctx.as_raw()) };
        if result == 0 { Some((x, y)) } else { None }
    }

    #[inline]
    pub fn on_curve(&self, ctx: &Context) -> bool {
        unsafe { ffi::gcry_mpi_ec_curve_point(self.as_raw(), ctx.as_raw()) != 0 }
    }

    #[inline]
    pub fn add(self, other: &Point, ctx: &Context) -> Point {
        unsafe {
            ffi::gcry_mpi_ec_add(self.as_raw(), self.as_raw(), other.as_raw(), ctx.as_raw());
        }
        self
    }

    #[inline]
    pub fn mul(self, n: &Integer, ctx: &Context) -> Point {
        unsafe {
            ffi::gcry_mpi_ec_mul(self.as_raw(), n.as_raw(), self.as_raw(), ctx.as_raw());
        }
        self
    }
}
