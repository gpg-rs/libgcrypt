use std::ptr;

use libc;
use ffi;

use Wrapper;
use super::Integer;

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
        let (x, y, z) = self.coords();
        let point = unsafe {
            Point::from_raw(ffi::gcry_mpi_point_snatch_set(ptr::null_mut(), x.into_raw(),
                                                           y.into_raw(), z.into_raw()))
        };
        point
    }

    fn clone_from(&mut self, source: &Point) {
        let (x, y, z) = source.coords();
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
    pub fn zero() -> Point {
        Point::new(0)
    }

    pub fn new(nbits: usize) -> Point {
        unsafe {
            Point {
                raw: ffi::gcry_mpi_point_new(nbits as libc::c_uint)
            }
        }
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

    pub fn coords(&self) -> (Integer, Integer, Integer) {
        let x = Integer::default();
        let y = Integer::default();
        let z = Integer::default();
        unsafe {
            ffi::gcry_mpi_point_get(x.as_raw(), y.as_raw(), z.as_raw(), self.raw);
        }
        (x, y, z)
    }

    pub fn into_coords(self) -> (Integer, Integer, Integer) {
        let x = Integer::default();
        let y = Integer::default();
        let z = Integer::default();
        unsafe {
            ffi::gcry_mpi_point_snatch_get(x.as_raw(), y.as_raw(), z.as_raw(), self.into_raw());
        }
        (x, y, z)
    }
}

impl Default for Point {
    fn default() -> Point {
        Point::new(0)
    }
}
