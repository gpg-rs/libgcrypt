use std::cmp::Ordering;
use std::fmt;
use std::ops;
use std::ptr;
use std::str;

use cstr_argument::CStrArgument;
use ffi;
use libc::c_uint;

use {Error, NonZero, Result};
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

pub struct Integer(NonZero<ffi::gcry_mpi_t>);

impl Drop for Integer {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_mpi_release(self.as_raw());
        }
    }
}

impl Clone for Integer {
    #[inline]
    fn clone(&self) -> Integer {
        unsafe { Integer::from_raw(ffi::gcry_mpi_copy(self.as_raw())) }
    }

    #[inline]
    fn clone_from(&mut self, source: &Integer) {
        unsafe {
            ffi::gcry_mpi_set(self.as_raw(), source.as_raw());
        }
    }
}

impl Integer {
    impl_wrapper!(Integer: ffi::gcry_mpi_t);

    #[inline]
    pub fn zero() -> Integer {
        Integer::new(0)
    }

    #[inline]
    pub fn one() -> Integer {
        Integer::from_uint(1)
    }

    #[inline]
    pub fn new(nbits: u32) -> Integer {
        let _ = ::get_token();
        unsafe { Integer::from_raw(ffi::gcry_mpi_new(nbits.into())) }
    }

    #[inline]
    pub fn new_secure(nbits: u32) -> Integer {
        let _ = ::get_token();
        unsafe { Integer::from_raw(ffi::gcry_mpi_snew(nbits.into())) }
    }

    #[inline]
    pub fn from_uint(n: u32) -> Integer {
        let _ = ::get_token();
        unsafe { Integer::from_raw(ffi::gcry_mpi_set_ui(ptr::null_mut(), n.into())) }
    }

    #[inline]
    pub fn from_bytes<B: AsRef<[u8]>>(format: Format, bytes: B) -> Result<Integer> {
        let bytes = bytes.as_ref();
        let _ = ::get_token();
        unsafe {
            let mut raw = ptr::null_mut();
            let len = if format != Format::Hex {
                bytes.len()
            } else if bytes.contains(&0) {
                0
            } else {
                return Err(Error::INV_ARG);
            };
            return_err!(ffi::gcry_mpi_scan(
                &mut raw,
                format as ffi::gcry_mpi_format,
                bytes.as_ptr() as *const _,
                len,
                ptr::null_mut()
            ));
            Ok(Integer::from_raw(raw))
        }
    }

    #[inline]
    pub fn from_str<S: CStrArgument>(s: S) -> Result<Integer> {
        let s = s.into_cstr();
        Integer::from_bytes(Format::Hex, s.as_ref().to_bytes_with_nul())
    }

    #[inline]
    pub fn to_bytes(&self, format: Format) -> Result<Buffer> {
        unsafe {
            let mut buffer = ptr::null_mut();
            let mut len = 0;
            return_err!(ffi::gcry_mpi_aprint(
                format as ffi::gcry_mpi_format,
                &mut buffer,
                &mut len,
                self.as_raw()
            ));
            Ok(Buffer::from_raw(buffer as *mut u8, len))
        }
    }

    #[inline]
    pub fn len_encoded(&self, format: Format) -> Result<usize> {
        unsafe {
            let mut len = 0;
            return_err!(ffi::gcry_mpi_print(
                format as ffi::gcry_mpi_format,
                ptr::null_mut(),
                0,
                &mut len,
                self.as_raw()
            ));
            Ok(len)
        }
    }

    #[inline]
    pub fn encode(&self, format: Format, buf: &mut [u8]) -> Result<usize> {
        unsafe {
            let mut written = 0;
            return_err!(ffi::gcry_mpi_print(
                format as ffi::gcry_mpi_format,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                &mut written,
                self.as_raw()
            ));
            Ok(written)
        }
    }

    #[inline]
    pub fn set(&mut self, n: u32) {
        unsafe {
            ffi::gcry_mpi_set_ui(self.as_raw(), n.into());
        }
    }

    #[inline]
    pub fn randomize(&mut self, nbits: u32, level: Level) {
        unsafe {
            ffi::gcry_mpi_randomize(self.as_raw(), nbits.into(), level.raw());
        }
    }

    #[inline]
    pub fn num_bits(&self) -> usize {
        unsafe { ffi::gcry_mpi_get_nbits(self.as_raw()) as usize }
    }

    #[inline]
    pub fn is_prime(&self) -> bool {
        unsafe { ffi::gcry_prime_check(self.as_raw(), 0) == 0 }
    }

    #[inline]
    pub fn is_positive(&self) -> bool {
        unsafe { ffi::gcry_mpi_cmp_ui(self.as_raw(), 0) > 0 }
    }

    #[inline]
    pub fn is_negative(&self) -> bool {
        unsafe { ffi::gcry_mpi_cmp_ui(self.as_raw(), 0) < 0 }
    }

    #[inline]
    pub fn abs(self) -> Integer {
        unsafe {
            ffi::gcry_mpi_abs(self.as_raw());
        }
        self
    }

    #[inline]
    pub fn add_mod(self, other: &Integer, m: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_addm(self.as_raw(), self.as_raw(), other.as_raw(), m.as_raw());
        }
        self
    }

    #[inline]
    pub fn sub_mod(self, other: &Integer, m: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_subm(self.as_raw(), self.as_raw(), other.as_raw(), m.as_raw());
        }
        self
    }

    #[inline]
    pub fn mul_mod(self, other: &Integer, m: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_mulm(self.as_raw(), self.as_raw(), other.as_raw(), m.as_raw());
        }
        self
    }

    #[inline]
    pub fn inv_mod(self, m: &Integer) -> Option<Integer> {
        let result = unsafe { ffi::gcry_mpi_invm(self.as_raw(), self.as_raw(), m.as_raw()) };
        if result != 0 {
            Some(self)
        } else {
            None
        }
    }

    #[inline]
    pub fn div_floor(self, other: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_div(
                self.as_raw(),
                ptr::null_mut(),
                self.as_raw(),
                other.as_raw(),
                -1,
            );
        }
        self
    }

    #[inline]
    pub fn mod_floor(self, other: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_div(
                ptr::null_mut(),
                self.as_raw(),
                self.as_raw(),
                other.as_raw(),
                -1,
            );
        }
        self
    }

    #[inline]
    pub fn div_rem(self, other: &Integer) -> (Integer, Integer) {
        let rem = Integer::zero();
        unsafe {
            ffi::gcry_mpi_div(
                self.as_raw(),
                rem.as_raw(),
                self.as_raw(),
                other.as_raw(),
                0,
            );
        }
        (self, rem)
    }

    #[inline]
    pub fn div_mod_floor(self, other: &Integer) -> (Integer, Integer) {
        let rem = Integer::zero();
        unsafe {
            ffi::gcry_mpi_div(
                self.as_raw(),
                rem.as_raw(),
                self.as_raw(),
                other.as_raw(),
                -1,
            );
        }
        (self, rem)
    }

    #[inline]
    pub fn ldexp(self, e: u32) -> Integer {
        unsafe {
            ffi::gcry_mpi_mul_2exp(self.as_raw(), self.as_raw(), e.into());
        }
        self
    }

    #[inline]
    pub fn pow_mod(self, e: &Integer, m: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_powm(self.as_raw(), self.as_raw(), e.as_raw(), m.as_raw());
        }
        self
    }

    #[inline]
    pub fn gcd(self, other: &Integer) -> Integer {
        unsafe {
            ffi::gcry_mpi_gcd(self.as_raw(), self.as_raw(), other.as_raw());
        }
        self
    }

    #[inline]
    pub fn lcm(self, other: &Integer) -> Integer {
        (self.clone() * other) / self.gcd(other)
    }
}

impl fmt::Debug for Integer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut s = f.debug_struct("Integer");
        s.field("raw", &self.0);
        if let Ok(bytes) = self.to_bytes(Format::Hex) {
            s.field("hex", &str::from_utf8(&bytes[..(bytes.len() - 1)]).unwrap());
        }
        s.finish()
    }
}

impl PartialEq<u32> for Integer {
    #[inline]
    fn eq(&self, other: &u32) -> bool {
        self.partial_cmp(other).unwrap() == Ordering::Equal
    }
}

impl PartialEq<Integer> for u32 {
    #[inline]
    fn eq(&self, other: &Integer) -> bool {
        self.partial_cmp(other).unwrap() == Ordering::Equal
    }
}

impl PartialOrd<u32> for Integer {
    #[inline]
    fn partial_cmp(&self, other: &u32) -> Option<Ordering> {
        let result = unsafe { ffi::gcry_mpi_cmp_ui(self.as_raw(), (*other).into()) };
        match result {
            x if x < 0 => Some(Ordering::Less),
            x if x > 0 => Some(Ordering::Greater),
            _ => Some(Ordering::Equal),
        }
    }
}

impl PartialOrd<Integer> for u32 {
    #[inline]
    fn partial_cmp(&self, other: &Integer) -> Option<Ordering> {
        other.partial_cmp(self).map(Ordering::reverse)
    }
}

impl PartialEq for Integer {
    #[inline]
    fn eq(&self, other: &Integer) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Integer {}

impl PartialOrd for Integer {
    #[inline]
    fn partial_cmp(&self, other: &Integer) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Integer {
    #[inline]
    fn cmp(&self, other: &Integer) -> Ordering {
        let result = unsafe { ffi::gcry_mpi_cmp(self.as_raw(), other.as_raw()) };
        match result {
            x if x < 0 => Ordering::Less,
            x if x > 0 => Ordering::Greater,
            _ => Ordering::Equal,
        }
    }
}

impl ops::Neg for Integer {
    type Output = Integer;

    #[inline]
    fn neg(self) -> Integer {
        unsafe {
            ffi::gcry_mpi_neg(self.as_raw(), self.as_raw());
        }
        self
    }
}

impl<'a> ops::Neg for &'a Integer {
    type Output = Integer;

    #[inline]
    fn neg(self) -> Integer {
        self.clone().neg()
    }
}

macro_rules! impl_binary_op {
    ($imp:ident, $method:ident, $body:expr) => {
        impl ops::$imp for Integer {
            type Output = Integer;

            #[inline]
            fn $method(self, other: Integer) -> Integer {
                self.$method(&other)
            }
        }
        impl<'a> ops::$imp<Integer> for &'a Integer {
            type Output = Integer;

            #[inline]
            fn $method(self, other: Integer) -> Integer {
                self.clone().$method(&other)
            }
        }

        impl<'a> ops::$imp<&'a Integer> for Integer {
            type Output = Integer;

            #[inline]
            fn $method(self, other: &'a Integer) -> Integer {
                unsafe {
                    $body(self.as_raw(), other.as_raw());
                }
                self
            }
        }
    };
}
impl_binary_op!(Add, add, |x, y| ffi::gcry_mpi_add(x, x, y));
impl_binary_op!(Sub, sub, |x, y| ffi::gcry_mpi_sub(x, x, y));
impl_binary_op!(Mul, mul, |x, y| ffi::gcry_mpi_mul(x, x, y));
impl_binary_op!(Div, div, |x, y| ffi::gcry_mpi_div(
    x,
    ptr::null_mut(),
    x,
    y,
    0
));
impl_binary_op!(Rem, rem, |x, y| ffi::gcry_mpi_mod(x, x, y));

impl ops::Shl<usize> for Integer {
    type Output = Integer;

    #[inline]
    fn shl(self, other: usize) -> Integer {
        unsafe {
            ffi::gcry_mpi_lshift(self.as_raw(), self.as_raw(), other as c_uint);
        }
        self
    }
}

impl ops::Shr<usize> for Integer {
    type Output = Integer;

    #[inline]
    fn shr(self, other: usize) -> Integer {
        unsafe {
            ffi::gcry_mpi_rshift(self.as_raw(), self.as_raw(), other as c_uint);
        }
        self
    }
}
