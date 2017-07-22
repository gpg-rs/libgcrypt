macro_rules! try_opt {
    ($e:expr) => (match $e { Some(v) => v, None => return None });
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
        pub type NonZero<T> = ::core::nonzero::NonZero<T>;
    } else {
        #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct NonZero<T>(T);

        impl<T> NonZero<T> {
            #[inline(always)]
            pub unsafe fn new(inner: T) -> NonZero<T> {
                NonZero(inner)
            }

            pub fn get(self) -> T {
                self.0
            }
        }
    }
}
