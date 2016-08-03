use std::cmp::Ordering;
use std::ffi::CString;
use std::fmt;
use std::ops;
use std::ptr;
use std::str;

use ffi;
use libc::c_uint;

use {Wrapper, Token};
use error::{self, Error, Result};
use buffer::Buffer;
use rand::Level;

#[repr(usize)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Format {
    Standard = ffi::GCRYMPI_FMT_STD as usize,
    Unsigned = ffi::GCRYMPI_FMT_USG as usize,
    Pgp = ffi::GCRYMPI_FMT_PGP as usize,
    Ssh = ffi::GCRYMPI_FMT_SSH as usize,
    Hex = ffi::GCRYMPI_FMT_HEX as usize,
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
        unsafe { Integer::from_raw(ffi::gcry_mpi_copy(self.raw)) }
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
    pub fn zero(token: Token) -> Integer {
        Integer::new(token, 0)
    }

    pub fn one(token: Token) -> Integer {
        Integer::from_uint(token, 1)
    }

    pub fn new(_: Token, nbits: u32) -> Integer {
        unsafe { Integer { raw: ffi::gcry_mpi_new(nbits.into()) } }
    }

    pub fn new_secure(_: Token, nbits: u32) -> Integer {
        unsafe { Integer { raw: ffi::gcry_mpi_snew(nbits.into()) } }
    }

    pub fn from_uint(_: Token, n: u32) -> Integer {
        unsafe { Integer::from_raw(ffi::gcry_mpi_set_ui(ptr::null_mut(), n.into())) }
    }

    pub fn from_bytes<B: ?Sized>(_: Token, format: Format, bytes: &B) -> Result<Integer>
    where B: AsRef<[u8]> {
        let bytes = bytes.as_ref();
        let mut raw: ffi::gcry_mpi_t = ptr::null_mut();
        unsafe {
            let len = if format != Format::Hex {
                bytes.len()
            } else if bytes.contains(&0) {
                0
            } else {
                return Err(Error::from_code(error::GPG_ERR_INV_ARG));
            };
            return_err!(ffi::gcry_mpi_scan(&mut raw,
                                           format as ffi::gcry_mpi_format,
                                           bytes.as_ptr() as *const _,
                                           len,
                                           ptr::null_mut()));
            Ok(Integer::from_raw(raw))
        }
    }

    pub fn from_str<S: Into<String>>(token: Token, s: S) -> Result<Integer> {
        let s = try!(CString::new(s.into()));
        Integer::from_bytes(token, Format::Hex, s.as_bytes_with_nul())
    }

    pub fn to_bytes(&self, format: Format) -> Result<Buffer> {
        unsafe {
            let mut buffer = ptr::null_mut();
            let mut len = 0;
            return_err!(ffi::gcry_mpi_aprint(format as ffi::gcry_mpi_format,
                                             &mut buffer,
                                             &mut len,
                                             self.raw));
            Ok(Buffer::from_raw(buffer as *mut u8, len))
        }
    }

    pub fn len_encoded(&self, format: Format) -> Result<usize> {
        unsafe {
            let mut len = 0;
            return_err!(ffi::gcry_mpi_print(format as ffi::gcry_mpi_format,
                                            ptr::null_mut(),
                                            0,
                                            &mut len,
                                            self.raw));
            Ok(len)
        }
    }

    pub fn encode(&self, format: Format, buf: &mut [u8]) -> Result<usize> {
        unsafe {
            let mut written = 0;
            return_err!(ffi::gcry_mpi_print(format as ffi::gcry_mpi_format,
                                            buf.as_mut_ptr() as *mut _,
                                            buf.len(),
                                            &mut written,
                                            self.raw));
            Ok(written)
        }
    }

    pub fn set(&mut self, n: u32) {
        unsafe {
            ffi::gcry_mpi_set_ui(self.raw, n.into());
        }
    }

    pub fn randomize(&mut self, nbits: u32, level: Level) {
        unsafe {
            ffi::gcry_mpi_randomize(self.raw, nbits.into(), level.raw());
        }
    }

    pub fn num_bits(&self) -> usize {
        unsafe { ffi::gcry_mpi_get_nbits(self.raw) as usize }
    }

    pub fn is_prime(&self) -> bool {
        unsafe { ffi::gcry_prime_check(self.raw, 0) == 0 }
    }

    pub fn is_positive(&self) -> bool {
        unsafe { ffi::gcry_mpi_cmp_ui(self.raw, 0) > 0 }
    }

    pub fn is_negative(&self) -> bool {
        unsafe { ffi::gcry_mpi_cmp_ui(self.raw, 0) < 0 }
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
        let result = unsafe { ffi::gcry_mpi_invm(self.raw, self.raw, m.raw) };
        if result != 0 { Some(self) } else { None }
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
        let rem = Integer::zero(::get_token().unwrap());
        unsafe {
            ffi::gcry_mpi_div(self.raw, rem.raw, self.raw, other.raw, 0);
        }
        (self, rem)
    }

    pub fn div_mod_floor(self, other: &Integer) -> (Integer, Integer) {
        let rem = Integer::zero(::get_token().unwrap());
        unsafe {
            ffi::gcry_mpi_div(self.raw, rem.raw, self.raw, other.raw, -1);
        }
        (self, rem)
    }

    pub fn ldexp(self, e: u32) -> Integer {
        unsafe {
            ffi::gcry_mpi_mul_2exp(self.raw, self.raw, e.into());
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

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let buffer = try!(self.to_bytes(Format::Hex).or(Err(fmt::Error)));
        f.write_str(str::from_utf8(&buffer[..(buffer.len() - 1)]).unwrap())
    }
}

impl PartialEq<u32> for Integer {
    fn eq(&self, other: &u32) -> bool {
        self.partial_cmp(other).unwrap() == Ordering::Equal
    }
}

impl PartialEq<Integer> for u32 {
    fn eq(&self, other: &Integer) -> bool {
        self.partial_cmp(other).unwrap() == Ordering::Equal
    }
}

impl PartialOrd<u32> for Integer {
    fn partial_cmp(&self, other: &u32) -> Option<Ordering> {
        let result = unsafe { ffi::gcry_mpi_cmp_ui(self.raw, (*other).into()) };
        match result {
            x if x < 0 => Some(Ordering::Less),
            x if x > 0 => Some(Ordering::Greater),
            _ => Some(Ordering::Equal),
        }
    }
}

impl PartialOrd<Integer> for u32 {
    fn partial_cmp(&self, other: &Integer) -> Option<Ordering> {
        match other.partial_cmp(self) {
            Some(Ordering::Less) => Some(Ordering::Greater),
            Some(Ordering::Greater) => Some(Ordering::Less),
            _ => Some(Ordering::Equal),
        }
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
        let result = unsafe { ffi::gcry_mpi_cmp(self.raw, other.raw) };
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
impl_binary_op!(Div, div,
                |x, y| ffi::gcry_mpi_div(x, ptr::null_mut(), x, y, 0));
impl_binary_op!(Rem, rem, |x, y| ffi::gcry_mpi_mod(x, x, y));

impl ops::Shl<usize> for Integer {
    type Output = Integer;

    fn shl(self, other: usize) -> Integer {
        unsafe {
            ffi::gcry_mpi_lshift(self.raw, self.raw, other as c_uint);
        }
        self
    }
}

impl ops::Shr<usize> for Integer {
    type Output = Integer;

    fn shr(self, other: usize) -> Integer {
        unsafe {
            ffi::gcry_mpi_rshift(self.raw, self.raw, other as c_uint);
        }
        self
    }
}
