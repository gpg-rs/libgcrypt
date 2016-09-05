use std::ffi::CStr;

use libc::c_char;

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

macro_rules! impl_wrapper {
    ($Name:ident: $Raw:ty) => {
        impl $Name {
            pub unsafe fn from_raw(raw: $Raw) -> Self {
                debug_assert!(!raw.is_null());
                $Name(raw)
            }

            pub fn as_raw(&self) -> $Raw {
                self.0
            }

            pub fn into_raw(self) -> $Raw {
                let raw = self.0;
                ::std::mem::forget(self);
                raw
            }
        }
    };
}

pub unsafe fn from_cstr<'a>(s: *const c_char) -> Option<&'a str> {
    if !s.is_null() {
        CStr::from_ptr(s).to_str().ok()
    } else {
        None
    }
}
