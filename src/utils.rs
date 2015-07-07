use std::ffi::CStr;
use std::str;

use libc;

macro_rules! try_opt {
    ($e:expr) => (match $e { Some(v) => v, None => return None });
}

macro_rules! enum_wrapper {
    ($(#[$Attr:meta])* pub enum $Name:ident: $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr),+
    }) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
        $(#[$Attr])*
        pub struct $Name($T);

        $($(#[$ItemAttr])* pub const $Item: $Name = $Name($Value as $T);)+

        impl $Name {
            pub unsafe fn from_raw(raw: $T) -> $Name {
                $Name(raw)
            }

            pub fn raw(&self) -> $T {
                self.0
            }
        }
    };
    ($(#[$Attr:meta])* pub enum $Name:ident: $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr,)+
    }) => {
        enum_wrapper! {
            $(#[$Attr])*
            pub enum $Name: $T {
                $($(#[$ItemAttr])* $Item = $Value),+
            }
        }
    };
}

pub unsafe fn from_cstr<'a>(s: *const libc::c_char) -> Option<&'a str> {
    if !s.is_null() {
        str::from_utf8(CStr::from_ptr(s).to_bytes()).ok()
    } else {
        None
    }
}
