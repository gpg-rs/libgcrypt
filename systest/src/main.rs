#![allow(bad_style, unused_imports, unused_macros)]
extern crate libc;
extern crate libgcrypt_sys;

use libc::*;
use libgcrypt_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
