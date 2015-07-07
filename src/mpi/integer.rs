use std::cmp::Ordering;
use std::ffi::CString;
use std::fmt;
use std::ops;
use std::ptr;
use std::str;

use libc;
use ffi;

use Wrapper;
use error::{Error, Result};
use buffer::Buffer;
use rand::Level;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Format {
    Standard = ffi::GCRYMPI_FMT_STD as isize,
    Unsigned = ffi::GCRYMPI_FMT_USG as isize,
    Pgp = ffi::GCRYMPI_FMT_PGP as isize,
    Ssh = ffi::GCRYMPI_FMT_SSH as isize,
    Hex = ffi::GCRYMPI_FMT_HEX as isize,
}

#[derive(Debug)]
pub struct Integer {
    raw: ffi::gcry_mpi_t,
}

impl Drop for Integer {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_mpi_release(self.raw);
        }
    }
}

impl Clone for Integer {
    fn clone(&self) -> Integer {
        unsafe {
            Integer::from_raw(ffi::gcry_mpi_copy(self.raw))
        }
    }

    fn clone_from(&mut self, source: &Integer) {
        unsafe {
            ffi::gcry_mpi_set(self.raw, source.raw);
        }
    }
}

unsafe impl Wrapper for Integer {
    type Raw = ffi::gcry_mpi_t;

    unsafe fn from_raw(raw: ffi::gcry_mpi_t) -> Integer {
        debug_assert!(!raw.is_null());
        Integer { raw: raw }
    }

    fn as_raw(&self) -> ffi::gcry_mpi_t {
        self.raw
    }
}

impl Integer {
    pub fn zero() -> Integer {
        Integer::new(0)
    }

    pub fn one() -> Integer {
        Integer::from(1)
    }

    pub fn new(nbits: usize) -> Integer {
        unsafe {
            Integer {
                raw: ffi::gcry_mpi_new(nbits as libc::c_uint)
            }
        }
    }

    pub fn new_secure(nbits: usize) -> Integer {
        unsafe {
            Integer {
                raw: ffi::gcry_mpi_snew(nbits as libc::c_uint)
            }
        }
    }

    pub fn from_bytes(format: Format, bytes: &[u8]) -> Result<Integer> {
        let mut raw: ffi::gcry_mpi_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_mpi_scan(&mut raw, format as ffi::gcry_mpi_format,
                                           bytes.as_ptr() as *const _,
                                           bytes.len() as libc::size_t,
                                           ptr::null_mut()));
            Ok(Integer::from_raw(raw))
        }
    }

    pub fn to_bytes(&self, format: Format) -> Result<Buffer> {
        unsafe {
            let mut buffer = ptr::null_mut();
            let mut len = 0 as libc::size_t;
            return_err!(ffi::gcry_mpi_aprint(format as ffi::gcry_mpi_format, &mut buffer,
                                             &mut len, self.raw));
            Ok(Buffer::from_raw(buffer as *mut u8, len as usize))
        }
    }

    pub fn set(&mut self, n: usize) {
        unsafe {
            ffi::gcry_mpi_set_ui(self.raw, n as libc::c_ulong);
        }
    }

    pub fn randomize(&mut self, nbits: usize, level: Level) {
        unsafe {
            ffi::gcry_mpi_randomize(self.raw, nbits as libc::c_uint, level.raw());
        }
    }

    pub fn num_bits(&self) -> usize {
        unsafe {
            ffi::gcry_mpi_get_nbits(self.raw) as usize
        }
    }

    pub fn is_prime(&self) -> bool {
        unsafe {
            ffi::gcry_prime_check(self.raw, 0) == 0
        }
    }

    pub fn is_positive(&self) -> bool {
        unsafe {
            ffi::gcry_mpi_cmp_ui(self.raw, 0) > 0
        }
    }

    pub fn is_negative(&self) -> bool {
        unsafe {
            ffi::gcry_mpi_cmp_ui(self.raw, 0) < 0
        }
    }

    pub fn abs(self) -> Integer {
        unsafe {
            ffi::gcry_mpi_abs(self.raw);
        }
        self
    }

    pub fn add_mod(self, other: &Integer, m: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_addm(self.raw, self.raw, other.raw, m.raw);
        }
        self
    }

    pub fn sub_mod(self, other: &Integer, m: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_subm(self.raw, self.raw, other.raw, m.raw);
        }
        self
    }

    pub fn mul_mod(self, other: &Integer, m: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_mulm(self.raw, self.raw, other.raw, m.raw);
        }
        self
    }

    pub fn inv_mod(self, m: &Integer) -> Option<Integer> {
        let result = unsafe {
            ffi::gcry_mpi_invm(self.raw, self.raw, m.raw)
        };
        if result != 0 {
            Some(self)
        } else {
            None
        }
    }

    pub fn div_floor(self, other: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_div(self.raw, ptr::null_mut(), self.raw, other.raw, -1);
        }
        self
    }

    pub fn mod_floor(self, other: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_div(ptr::null_mut(), self.raw, self.raw, other.raw, -1);
        }
        self
    }

    pub fn div_rem(self, other: &Integer) -> (Integer, Integer) {
        let rem = Integer::default();
        unsafe {
            ffi::gcry_mpi_div(self.raw, rem.raw, self.raw, other.raw, 0);
        }
        (self, rem)
    }

    pub fn div_mod_floor(self, other: &Integer) -> (Integer, Integer) {
        let rem = Integer::default();
        unsafe {
            ffi::gcry_mpi_div(self.raw, rem.raw, self.raw, other.raw, -1);
        }
        (self, rem)
    }

    pub fn ldexp(self, e: usize) -> Integer {
        unsafe {
            ffi::gcry_mpi_mul_2exp(self.raw, self.raw, e as libc::c_ulong);
        }
        self
    }

    pub fn pow_mod(self, e: &Integer, m: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_powm(self.raw, self.raw, e.raw, m.raw);
        }
        self
    }

    pub fn gcd(self, other: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_gcd(self.raw, self.raw, other.raw);
        }
        self
    }

    pub fn lcm(self, other: &Integer) -> Integer {
        (self.clone() * other) / self.gcd(other)
    }
}

impl Default for Integer {
    fn default() -> Integer {
        Integer::new(0)
    }
}

impl From<usize> for Integer {
    fn from(n: usize) -> Integer {
        unsafe {
            Integer::from_raw(ffi::gcry_mpi_set_ui(ptr::null_mut(), n as libc::c_ulong))
        }
    }
}

impl str::FromStr for Integer {
    type Err = Error;

    fn from_str(s: &str) -> Result<Integer> {
        let s = try!(CString::new(s));
        let mut raw: ffi::gcry_mpi_t = ptr::null_mut();
        unsafe {
            return_err!(ffi::gcry_mpi_scan(&mut raw, ffi::GCRYMPI_FMT_HEX, s.as_ptr() as *const _,
                                           0, ptr::null_mut()));
            Ok(Integer::from_raw(raw))
        }
    }
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let buffer = unsafe {
            let mut buffer = ptr::null_mut();
            let mut len = 0 as libc::size_t;
            if ffi::gcry_mpi_aprint(ffi::GCRYMPI_FMT_HEX, &mut buffer, &mut len, self.raw) != 0 {
                return Err(fmt::Error);
            }
            Buffer::from_raw(buffer as *mut u8, (len - 1) as usize)
        };
        f.write_str(str::from_utf8(&*buffer).unwrap())
    }
}

impl PartialEq for Integer {
    fn eq(&self, other: &Integer) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Integer {}

impl PartialOrd for Integer {
    fn partial_cmp(&self, other: &Integer) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Integer {
    fn cmp(&self, other: &Integer) -> Ordering {
        let result = unsafe {
            ffi::gcry_mpi_cmp(self.raw, other.raw)
        };
        match result {
            x if x < 0 => Ordering::Less,
            x if x > 0 => Ordering::Greater,
            _ => Ordering::Equal,
        }
    }
}

impl ops::Neg for Integer {
    type Output = Integer;

    fn neg(self) -> Integer {
        unsafe {
            ffi::gcry_mpi_neg(self.raw, self.raw);
        }
        self
    }
}

impl<'a> ops::Neg for &'a Integer {
    type Output = Integer;

    fn neg(self) -> Integer {
        self.clone().neg()
    }
}

macro_rules! impl_binary_op {
    ($imp:ident, $method:ident, $body:expr) => {
        impl ops::$imp for Integer {
            type Output = Integer;

            fn $method(self, other: Integer) -> Integer {
                self.$method(&other)
            }
        }
        impl<'a> ops::$imp<Integer> for &'a Integer {
            type Output = Integer;

            fn $method(self, other: Integer) -> Integer {
                self.clone().$method(&other)
            }
        }

        impl<'a> ops::$imp<&'a Integer> for Integer {
            type Output = Integer;

            fn $method(self, other: &'a Integer) -> Integer {
                unsafe {
                    $body(self.raw, other.raw);
                }
                self
            }
        }
    };
}
impl_binary_op!(Add, add, |x, y| ffi::gcry_mpi_add(x, x, y));
impl_binary_op!(Sub, sub, |x, y| ffi::gcry_mpi_sub(x, x, y));
impl_binary_op!(Mul, mul, |x, y| ffi::gcry_mpi_mul(x, x, y));
impl_binary_op!(Div, div, |x, y| ffi::gcry_mpi_div(x, ptr::null_mut(), x, y, 0));
impl_binary_op!(Rem, rem, |x, y| ffi::gcry_mpi_mod(x, x, y));

impl ops::Shl<usize> for Integer {
    type Output = Integer;

    fn shl(self, other: usize) -> Integer {
        unsafe {
            ffi::gcry_mpi_lshift(self.raw, self.raw, other as libc::c_uint);
        }
        self
    }
}

impl ops::Shr<usize> for Integer {
    type Output = Integer;

    fn shr(self, other: usize) -> Integer {
        unsafe {
            ffi::gcry_mpi_rshift(self.raw, self.raw, other as libc::c_uint);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::Integer;

    #[test]
    fn test_print() {
        assert_eq!(Integer::zero().to_string(), "00");
        assert_eq!(Integer::from(0xabcdef).to_string(), "00ABCDEF");
    }
}
