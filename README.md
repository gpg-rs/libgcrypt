# rust-gcrypt

[![Build Status](https://travis-ci.org/johnschug/rust-gcrypt.svg?branch=master)](https://travis-ci.org/johnschug/rust-gcrypt)
[![LGPL-2.1 licensed](https://img.shields.io/badge/license-LGPL--2.1-blue.svg)](./COPYING)
[![crates.io](https://meritbadge.herokuapp.com/gcrypt)](https://crates.io/crates/gcrypt)

[Libgcrypt](https://www.gnu.org/software/libgcrypt/) bindings for Rust.

[Documentation](http://johnschug.github.io/rust-gcrypt)

Version 1.5.0 or greater of libgcrypt is required to use this wrapper.
Some features may require a more recent version.

The libgcrypt-sys crate will attempt to find the library by parsing the output
of `libgcrypt-config`. The path to the library and its header files can also be
configured by setting the environment variables `LIBGCRYPT_LIB` and
`LIBGCRYPT_INCLUDE_DIR` before building the crate. A working installation of
gcc is also required.

The required libraries and binaries can be installed by running:

#### Debian / Ubuntu
```shell
$ sudo apt-get install libgcrypt11-dev
```
or
```shell
$ sudo apt-get install libgcrypt20-dev
```

#### RHEL / CentOS / Fedora
```shell
$ sudo yum install libgcrypt-devel
```

#### Mac OS X
```shell
$ brew install libgcrypt
```

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
