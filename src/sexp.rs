use std::ffi::CString;
use std::fmt;
use std::mem;
use std::ptr;
use std::slice;
use std::str;

use libc;
use ffi;

use Wrapper;
use error::{self, Error, Result};
use mpi::Integer;
use mpi::integer::Format as IntegerFormat;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Format {
    Default = ffi::GCRYSEXP_FMT_DEFAULT as isize,
    Canonical = ffi::GCRYSEXP_FMT_CANON as isize,
    Base64 = ffi::GCRYSEXP_FMT_BASE64 as isize,
    Advanced = ffi::GCRYSEXP_FMT_ADVANCED as isize,
}

pub struct SExpression {
    raw: ffi::gcry_sexp_t,
}

impl Drop for SExpression {
    fn drop(&mut self) {
        unsafe {
            ffi::gcry_sexp_release(self.raw);
        }
    }
}

unsafe impl Wrapper for SExpression {
    type Raw = ffi::gcry_sexp_t;

    unsafe fn from_raw(raw: ffi::gcry_sexp_t) -> SExpression {
        debug_assert!(!raw.is_null());
        SExpression { raw: raw }
    }

    fn as_raw(&self) -> ffi::gcry_sexp_t {
        self.raw
    }
}

impl SExpression {
    pub fn from_bytes<B: ?Sized + AsRef<[u8]>>(bytes: &B) -> Result<SExpression> {
        let bytes = bytes.as_ref();
        unsafe {
            let mut result: ffi::gcry_sexp_t = ptr::null_mut();
            return_err!(ffi::gcry_sexp_new(&mut result, bytes.as_ptr() as *const _,
                                           bytes.len() as libc::size_t, 1));
            Ok(SExpression::from_raw(result))
        }
    }

    pub fn to_bytes(&self, format: Format) -> Vec<u8> {
        let mut buffer = vec![0; self.len_encoded(format)];
        self.encode(format, &mut buffer);
        buffer.pop();
        buffer
    }

    pub fn len_encoded(&self, format: Format) -> usize {
        unsafe {
            ffi::gcry_sexp_sprint(self.raw, format as libc::c_int, ptr::null_mut(), 0) as usize
        }
    }

    pub fn encode(&self, format: Format, buf: &mut [u8]) -> Option<usize> {
        unsafe {
            match ffi::gcry_sexp_sprint(self.raw, format as libc::c_int,
                                        buf.as_mut_ptr() as *mut _, buf.len() as libc::size_t) {
                0 => None,
                x => Some(x as usize),
            }
        }
    }

    pub fn elements(&self) -> Elements {
        Elements {
            sexp: self,
            first: 0,
            last: self.len(),
        }
    }

    pub fn head(&self) -> Option<SExpression> {
        unsafe {
            let result = ffi::gcry_sexp_car(self.raw);
            if !result.is_null() {
                Some(SExpression::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn tail(&self) -> Option<SExpression> {
        unsafe {
            let result = ffi::gcry_sexp_cdr(self.raw);
            if !result.is_null() {
                Some(SExpression::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn len(&self) -> usize {
        unsafe {
            ffi::gcry_sexp_length(self.raw) as usize
        }
    }

    pub fn find_token<B: ?Sized + AsRef<[u8]>>(&self, token: &B) -> Option<SExpression> {
        let token = token.as_ref();
        unsafe {
            let result = ffi::gcry_sexp_find_token(self.raw, token.as_ptr() as *const _,
                                                   token.len() as libc::size_t);
            if !result.is_null() {
                Some(SExpression::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn get(&self, idx: usize) -> Option<SExpression> {
        unsafe {
            let result = ffi::gcry_sexp_nth(self.raw, idx as libc::c_int);
            if !result.is_null() {
                Some(SExpression::from_raw(result))
            } else {
                None
            }
        }
    }

    pub fn get_bytes(&self, idx: usize) -> Option<&[u8]> {
        unsafe {
            let mut datalen: libc::size_t = 0;
            let result = ffi::gcry_sexp_nth_data(self.raw, idx as libc::c_int,
                                                 &mut datalen);
            if !result.is_null() {
                Some(slice::from_raw_parts(result as *const _, datalen as usize))
            } else {
                None
            }
        }
    }

    pub fn get_str(&self, idx: usize) -> Option<&str> {
        self.get_bytes(idx).and_then(|b| str::from_utf8(b).ok())
    }

    pub fn get_integer(&self, idx: usize, fmt: IntegerFormat) -> Option<Integer> {
        unsafe {
            let result = ffi::gcry_sexp_nth_mpi(self.raw, idx as libc::c_int,
                                                fmt as libc::c_int);
            if !result.is_null() {
                Some(Integer::from_raw(result))
            } else {
                None
            }
        }
    }
}

impl str::FromStr for SExpression {
    type Err = Error;

    fn from_str(s: &str) -> Result<SExpression> {
        unsafe {
            let mut result: ffi::gcry_sexp_t = ptr::null_mut();
            return_err!(ffi::gcry_sexp_sscan(&mut result, ptr::null_mut(), s.as_ptr() as *const _,
                                             s.len() as libc::size_t));
            Ok(SExpression::from_raw(result))
        }
    }
}

impl fmt::Display for SExpression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let result = self.to_bytes(Format::Advanced);
        if !result.is_empty() {
            f.write_str(&String::from_utf8_lossy(&result[..(result.len() - 1)]))
        } else {
            Ok(())
        }
    }
}

impl<'a> IntoIterator for &'a SExpression {
    type Item = SExpression;
    type IntoIter = Elements<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements()
    }
}

pub struct Elements<'a> {
    sexp: &'a SExpression,
    first: usize,
    last: usize,
}

impl<'a> Iterator for Elements<'a> {
    type Item = SExpression;

    fn next(&mut self) -> Option<Self::Item> {
        if self.first < self.last {
            let elem = unsafe {
                SExpression::from_raw(ffi::gcry_sexp_nth(self.sexp.as_raw(),
                                                         self.first as libc::c_int))
            };
            self.first += 1;
            Some(elem)
        } else {
            None
        }
    }

    fn last(mut self) -> Option<Self::Item> {
        self.next_back()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.first = self.first.saturating_add(n);
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.last - self.first;
        (size, Some(size))
    }
}
impl<'a> DoubleEndedIterator for Elements<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.first < self.last {
            self.last -= 1;
            unsafe {
                Some(SExpression::from_raw(ffi::gcry_sexp_nth(self.sexp.as_raw(),
                                                              self.first as libc::c_int)))
            }
        } else {
            None
        }
    }
}
impl<'a> ExactSizeIterator for Elements<'a> {}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
enum ParameterKind {
    Integer,
    Bytes,
    Mpi,
    SExpression,
}

enum Parameter {
    Integer(libc::c_int),
    Bytes(libc::c_int, *const libc::c_char),
    Mpi(ffi::gcry_mpi_t),
    SExpression(ffi::gcry_sexp_t),
}

#[derive(Debug, Clone)]
pub struct Template {
    format: CString,
    params: Vec<ParameterKind>,
}

impl Template {
    pub fn new(format: &str) -> Result<Template> {
        let mut new_format = Vec::with_capacity(format.len());
        let mut params = Vec::new();
        let mut it = format.bytes();
        loop {
            match it.next() {
                Some(b'%') => {
                    new_format.push(b'%');
                    let kind = match it.next() {
                        Some(x) if (x == b'd') || (x == b'u') => {
                            new_format.push(x);
                            ParameterKind::Integer
                        },
                        Some(b'b') | Some(b's') => {
                            new_format.push(b'b');
                            ParameterKind::Bytes
                        },
                        Some(x) if (x == b'm') || (x == b'M') => {
                            new_format.push(x);
                            ParameterKind::Mpi
                        },
                        Some(b'S') => {
                            new_format.push(b'S');
                            ParameterKind::SExpression
                        },
                        _ => return Err(Error::from_code(error::GPG_ERR_INV_ARG)),
                    };
                    params.push(kind);
                },
                Some(b'\0') => return Err(Error::from_code(error::GPG_ERR_INV_ARG)),
                Some(x) => new_format.push(x),
                None => break,
            }
        }
        unsafe {
            Ok(Template { format: CString::from_vec_unchecked(new_format), params: params })
        }
    }
}

pub struct Builder<'a> {
    template: &'a Template,
    params: Vec<Parameter>,
}

impl<'a> Builder<'a> {
    pub fn from<'b>(template: &'b Template) -> Builder<'b> {
        Builder { template: template, params: Vec::new() }
    }

    pub fn add_integer(&mut self, n: isize) -> &mut Self {
        if self.template.params.get(self.params.len()) != Some(&ParameterKind::Integer) {
            panic!();
        }
        self.params.push(Parameter::Integer(n as libc::c_int));
        self
    }

    pub fn add_bytes<'s, 'b: 's, B: ?Sized>(&'s mut self, bytes: &'b B) -> &mut Self
    where B: AsRef<[u8]> {
        if self.template.params.get(self.params.len()) != Some(&ParameterKind::Bytes) {
            panic!();
        }
        let bytes = bytes.as_ref();
        self.params.push(Parameter::Bytes(bytes.len() as libc::c_int, bytes.as_ptr() as *const _));
        self
    }

    pub fn add_mpi<'s, 'b: 's>(&'s mut self, n: &'b Integer) -> &mut Self {
        if self.template.params.get(self.params.len()) != Some(&ParameterKind::Mpi) {
            panic!();
        }
        self.params.push(Parameter::Mpi(n.as_raw()));
        self
    }

    pub fn add_sexp<'s, 'b: 's>(&'s mut self, s: &'b SExpression) -> &mut Self {
        if self.template.params.get(self.params.len()) != Some(&ParameterKind::SExpression) {
            panic!();
        }
        self.params.push(Parameter::SExpression(s.as_raw()));
        self
    }

    pub fn build(self) -> Result<SExpression> {
        if self.params.len() != self.template.params.len() {
            return Err(Error::from_code(error::GPG_ERR_INV_STATE));
        }
        unsafe {
            let mut args = Vec::<*mut libc::c_void>::with_capacity(self.params.len());
            for param in self.params.iter() {
                match param {
                    &Parameter::Integer(ref x) => args.push(mem::transmute(x)),
                    &Parameter::Bytes(ref len, ref data) => {
                        args.push(mem::transmute(len));
                        args.push(mem::transmute(data));
                    },
                    &Parameter::Mpi(ref x) => args.push(mem::transmute(x)),
                    &Parameter::SExpression(ref s) => args.push(mem::transmute(s)),
                }
            }
            args.push(ptr::null_mut());

            let mut result: ffi::gcry_sexp_t = ptr::null_mut();
            return_err!(ffi::gcry_sexp_build_array(&mut result, ptr::null_mut(),
                                                   self.template.format.as_ptr(),
                                                   args.as_mut_ptr()));
            Ok(SExpression::from_raw(result))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build() {
        let template = Template::new("(private-key(ecc(curve %s)(flags eddsa)(q %b)(d %b)))").unwrap();
        let mut builder = Builder::from(&template);
        builder.add_bytes("Ed25519").add_bytes("124124").add_bytes("2324");
        let result = builder.build().unwrap();
        println!("{}", result);
    }
}
