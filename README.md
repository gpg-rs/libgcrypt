# libgcrypt-rs

[![Build Status][build]][ci]
[![crates.io version][version]][crate]
[![LGPL-2.1 licensed][license]](./COPYING)
[![downloads][downloads]][crate]

[Libgcrypt][upstream] bindings for Rust.

[Documentation][docs]

## Building
These crates require the libgcrypt library and its development files (e.g.,
headers, libgcrypt-config) to be installed. The buildscript will attempt to
detect the necessary information using the `libgcrypt-config` script
distributed with libgcrypt. If for whatever reason this does not work, the
required information can also be specified using one or more environment
variables:
- `LIBGCRYPT_INCLUDE` specifies the path(s) where header files can be found.
- `LIBGCRYPT_LIB_DIR` specifies the path(s) where library files (e.g., *.so, *.a,
  *.dll, etc.) can be found.
- `LIBGCRYPT_LIBS` specifies the name(s) of all required libraries.
- `LIBGCRYPT_STATIC` controls whether libraries are linked to statically or
  dynamically by default. Individual libraries can have their linkage
  overridden by prefixing their names with either `static=` or `dynamic=` in
  `LIBGCRYPT_LIBS`.
- `LIBGCRYPT_CONFIG` specifies the path to the `libgcrypt-config` script.

Each environment variable, with the exceptions of `LIBGCRYPT_STATIC` and
`LIBGCRYPT_CONFIG`, can take multiple values separated by the platform's path
separator.

**NOTE**: These crates also depend on the gpg-error crate which has its own
[requirements](https://github.com/gpg-rs/libgpg-error).

**NOTE**: Previous versions of these crates bundled the sources of the
libgcrypt library and attempted to build them via the buildscript. This is no
longer supported.

## Usage
The library requires initialization before first use. The functions `init`,
`init_fips`, and `init_default` can be used to initialize the library. The
closure passed to the first two functions is used to configure the library. For
the third function a default configuration is used. More information on
configuration options can be found in the libgcrypt [documentation][upstream docs].

An example:

```rust
let token = gcrypt::init(|x| {
    x.disable_secmem();
});
```

Calling any function in the wrapper that requires initialization before one of
the initialization functions has been called will cause the wrapper to attempt
to initialize the library with a call to `init_default`.

[crate]: https://crates.io/crates/gcrypt
[ci]: https://github.com/gpg-rs/libgcrypt/actions?query=branch%3Amaster
[build]: https://img.shields.io/github/workflow/status/gpg-rs/libgcrypt/ci?style=flat-square
[version]: https://img.shields.io/crates/v/gcrypt?style=flat-square
[license]: https://img.shields.io/crates/l/gcrypt?style=flat-square
[downloads]: https://img.shields.io/crates/d/gcrypt?style=flat-square

[upstream]: https://www.gnu.org/software/libgcrypt/
[docs]: https://docs.rs/gcrypt
[upstream docs]: https://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library
