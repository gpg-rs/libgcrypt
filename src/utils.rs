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
    ($Name:ident: $T:ty) => {
        #[inline]
        pub unsafe fn from_raw(raw: $T) -> Self {
            debug_assert!(!raw.is_null());
            $Name(NonZero::new(raw))
        }

        #[inline]
        pub fn as_raw(&self) -> $T {
            *self.0
        }

        #[inline]
        pub fn into_raw(self) -> $T {
            let raw = *self.0;
            ::std::mem::forget(self);
            raw
        }
    };
}

pub unsafe fn from_cstr<'a>(s: *const c_char) -> Option<&'a str> {
    s.as_ref().and_then(|s| CStr::from_ptr(s).to_str().ok())
}

cfg_if! {
    if #[cfg(any(nightly, feature = "nightly"))] {
        pub type NonZero<T> = ::core::nonzero::NonZero<T>;
    } else {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct NonZero<T>(T);

        impl<T> NonZero<T> {
            #[inline(always)]
            pub unsafe fn new(inner: T) -> NonZero<T> {
                NonZero(inner)
            }
        }

        impl<T> ::std::ops::Deref for NonZero<T> {
            type Target = T;

            fn deref(&self) -> &T {
                &self.0
            }
        }
    }
}
