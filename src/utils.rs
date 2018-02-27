include!(concat!(env!("OUT_DIR"), "/version.rs"));

macro_rules! impl_wrapper {
    ($Name:ident: $T:ty) => {
        #[inline]
        pub unsafe fn from_raw(raw: $T) -> Self {
            $Name(NonNull::<$T>::new(raw).unwrap())
        }

        #[inline]
        pub fn as_raw(&self) -> $T {
            self.0.as_ptr()
        }

        #[inline]
        pub fn into_raw(self) -> $T {
            let raw = self.as_raw();
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

pub(crate) trait Ptr {
    type Inner;
}

impl<T> Ptr for *mut T {
    type Inner = T;
}

impl<T> Ptr for *const T {
    type Inner = T;
}

pub(crate) type NonNull<T> = details::NonNull<<T as Ptr>::Inner>;

mod details {
    cfg_if! {
        if #[cfg(any(nightly, feature = "nightly"))] {
            pub type NonNull<T> = ::std::ptr::NonNull<T>;
        } else {
            use std::fmt;

            pub struct NonNull<T>(*const T);

            impl<T> NonNull<T> {
                #[inline(always)]
                pub fn new(inner: *mut T) -> Option<Self> {
                    if inner.is_null() {
                        None
                    } else {
                        Some(NonNull(inner))
                    }
                }

                pub fn as_ptr(&self) -> *mut T {
                    self.0 as *mut T
                }
            }

            impl<T> Copy for NonNull<T> {}
            impl<T> Clone for NonNull<T> {
                fn clone(&self) -> Self {
                    *self
                }
            }

            impl<T> fmt::Debug for NonNull<T> {
                fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    fmt::Pointer::fmt(&self.as_ptr(), f)
                }
            }
        }
    }
}
