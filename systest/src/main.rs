#![allow(bad_style, unused_imports, unused_macros)]

use libc::*;
use libgcrypt_sys::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
