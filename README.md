# rust-gcrypt

[![Build Status](https://travis-ci.org/johnschug/rust-gcrypt.svg?branch=master)](https://travis-ci.org/johnschug/rust-gcrypt)
[![LGPL-2.1 licensed](https://img.shields.io/badge/license-LGPL--2.1-blue.svg)](./COPYING)
[![crates.io](https://meritbadge.herokuapp.com/gcrypt)](https://crates.io/crates/gcrypt)

[Libgcrypt](https://www.gnu.org/software/libgcrypt/) bindings for Rust.

[Documentation](http://johnschug.github.io/rust-gcrypt)

Version 1.5.0 or greater of libgcrypt is required to use this wrapper.
Some features may require a more recent version.

The libgcrypt-sys crate requires the libgcrypt-config binary to be executable in order to
build the crate. The path to this binary can be set using the environment variable LIBGCRYPT_CONFIG.
A working installation of gcc is also required.

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
gcrypt = "0.1"
```

And this in your crate root:

```rust
extern crate gcrypt;
```

The library **must** be initialized using [```gcrypt::init```](https://johnschug.github.io/rust-gcrypt/gcrypt/fn.init.html) or
[```gcrypt::init_fips_mode```](https://johnschug.github.io/rust-gcrypt/gcrypt/fn.init_fips_mode.html)
before using any other function in the library or wrapper. An example of initialization can be found in
the [```setup```](./tests/basic.rs#L17) function in tests/basic.rs
(NB: the ```enable_quick_random``` option should **not** be used in most cases). More information on
initialization can be found in the libgcrypt [documentation](https://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html#Initializing-the-library).
