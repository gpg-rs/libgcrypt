# rust-gcrypt

[![Build Status](https://travis-ci.org/johnschug/rust-gcrypt.svg?branch=master)](https://travis-ci.org/johnschug/rust-gcrypt)
[![Build status](https://ci.appveyor.com/api/projects/status/bbdwaqw7xo6hbp76/branch/master?svg=true)](https://ci.appveyor.com/project/johnschug/rust-gcrypt/branch/master)
[![LGPL-2.1 licensed](https://img.shields.io/badge/license-LGPL--2.1-blue.svg)](./COPYING)
[![crates.io](https://meritbadge.herokuapp.com/gcrypt)](https://crates.io/crates/gcrypt)

[Libgcrypt](https://www.gnu.org/software/libgcrypt/) bindings for Rust.

[Documentation](http://johnschug.github.io/rust-gcrypt)

## Requirements

The wrapper is usable with libgcrypt 1.5.0 or later. Some features may require
a more recent version.

By default, the libgcrypt-sys crate will attempt to build the latest version of
the library from source using autoconf and automake. An existing installation
may be specified using `LIBGCRYPT_LIB`, `LIBGCRYPT_STATIC` (optional) and
`LIBGCRYPT_INCLUDE_DIR`. Alternatively the path to the libgcrypt configuration
program (`libgcrypt-config`) may be specified using `LIBGCRYPT_CONFIG`.

## Usage

Put this in your `Cargo.toml`:

```toml
[dependencies]
gcrypt = "0.4"
```

And this in your crate root:

```rust
extern crate gcrypt;
```

The library requires initialization before first use. The functions `init` and
`init_fips` can be used to initialize the library. The closure passed to these
functions is used to configure the library. More information on configuration
options can be found in the libgcrypt
[documentation](https://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library).

An example:

```rust
let token = gcrypt::init(|mut x| {
    x.disable_secmem();
});
```

Calling any function in the wrapper that requires initialization before `init`
or `init_fips` are called will cause the wrapper to attempt to initialize the
library with a default configuration.
