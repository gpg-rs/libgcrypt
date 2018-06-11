# libgcrypt-rs

[![Build Status](https://travis-ci.org/gpg-rs/libgcrypt.svg?branch=master)](https://travis-ci.org/gpg-rs/libgcrypt)
[![LGPL-2.1 licensed](https://img.shields.io/badge/license-LGPL--2.1-blue.svg)](./COPYING)
[![crates.io](https://meritbadge.herokuapp.com/gcrypt)](https://crates.io/crates/gcrypt)

[Libgcrypt][upstream] bindings for Rust.

[Documentation][docs]

## Requirements

The wrapper is usable with libgcrypt 1.5.0 or later. Some features may require
a more recent version.

By default, the libgcrypt-sys crate will attempt to build the bundled version
of the library from source using autoconf, automake and various C build tools.
The `bundled` feature flag controls this functionality and can be disabled by
using `no-default-features` in dependent crates and/or overridden by setting
the environment variable `LIBGCRYPT_USE_BUNDLED` to the empty string, `no`,
`off`, or `false` to disable or anything else to enable. An existing
installation may be specified using `LIBGCRYPT_LIB_DIR`, `LIBGCRYPT_LIBS`,
`LIBGCRYPT_STATIC` (optional) and `LIBGCRYPT_INCLUDE`. Alternatively the path
to the libgcrypt configuration program (`libgcrypt-config`) may be specified
using `LIBGCRYPT_CONFIG`.

## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies]
gcrypt = "0.5"
```

And this in your crate root:

```rust
extern crate gcrypt;
```

The library requires initialization before first use. The functions `init`,
`init_fips`, and `init_default` can be used to initialize the library. The
closure passed to the first two functions is used to configure the library. For
the third function a default configuration is used. More information on
configuration options can be found in the libgcrypt [documentation][upstream
docs].

An example:

```rust
let token = gcrypt::init(|x| {
    x.disable_secmem();
});
```

Calling any function in the wrapper that requires initialization before one of
the initialization functions has been called will cause the wrapper to attempt
to initialize the library with a call to `init_default`.

[upstream]: https://www.gnu.org/software/libgcrypt/
[docs]: https://docs.rs/gcrypt
[upstream docs]: https://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library
