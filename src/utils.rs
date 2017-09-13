include!(concat!(env!("OUT_DIR"), "/version.rs"));

macro_rules! impl_wrapper {
    ($Name:ident: $T:ty) => {
        #[inline]
        pub unsafe fn from_raw(raw: $T) -> Self {
            $Name(NonZero::new(raw).unwrap())
        }

        #[inline]
        pub fn as_raw(&self) -> $T {
            self.0.get()
        }

        #[inline]
        pub fn into_raw(self) -> $T {
            let raw = self.0.get();
            ::std::mem::forget(self);
            raw
        }
    };
}

macro_rules! ffi_enum_wrapper {
    ($(#[$Attr:meta])* pub enum $Name:ident: $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr),+
    }) => {
        #[derive(Copy, Clone, Eq, PartialEq, Hash)]
        $(#[$Attr])*
        pub enum $Name {
            $($(#[$ItemAttr])* $Item,)+
            Other($T),
        }

        impl $Name {
            #[inline]
            pub unsafe fn from_raw(raw: $T) -> $Name {
                $(if raw == ($Value as $T) {
                    $Name::$Item
                } else )+ {
                    $Name::Other(raw)
                }
            }

            #[inline]
            pub fn raw(&self) -> $T {
                match *self {
                    $($Name::$Item => $Value as $T,)+
                    $Name::Other(other) => other,
                }
            }
        }

        impl ::std::fmt::Debug for $Name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match *self {
                    $($Name::$Item => {
                        write!(f, concat!(stringify!($Name), "::",
                                          stringify!($Item), "({:?})"), self.raw())
                    })+
                    _ => write!(f, concat!(stringify!($Name), "({:?})"), self.raw()),
                }
            }
        }
    };
    ($(#[$Attr:meta])* pub enum $Name:ident: $T:ty {
        $($(#[$ItemAttr:meta])* $Item:ident = $Value:expr,)+
    }) => {
        ffi_enum_wrapper! {
            $(#[$Attr])*
            pub enum $Name: $T {
                $($(#[$ItemAttr])* $Item = $Value),+
            }
        }
    };
}

cfg_if! {
    if #[cfg(any(nightly, feature = "nightly"))] {
        pub use core::nonzero::NonZero;
    } else {
        pub unsafe trait Zeroable {
            fn is_zero(&self) -> bool;
        }

        unsafe impl<T: ?Sized> Zeroable for *mut T {
            #[inline]
            fn is_zero(&self) -> bool {
                (*self as *mut u8).is_null()
            }
        }

        unsafe impl<T: ?Sized> Zeroable for *const T {
            #[inline]
            fn is_zero(&self) -> bool {
                (*self as *mut u8).is_null()
            }
        }

        #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct NonZero<T: Zeroable>(T);

        impl<T: Zeroable> NonZero<T> {
            #[inline(always)]
            pub fn new(inner: T) -> Option<Self> {
                if inner.is_zero() {
                    None
                } else {
                    Some(NonZero(inner))
                }
            }

            pub fn get(self) -> T {
                self.0
            }
        }
    }
}
