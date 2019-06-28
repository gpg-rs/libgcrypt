#![allow(non_camel_case_types, non_upper_case_globals)]
extern crate libc;
extern crate libgpg_error_sys;

#[cfg(not(ctest))]
include!(concat!(env!("OUT_DIR"), "/version.rs"));

pub use self::consts::*;
pub use self::funcs::*;
pub use self::types::*;

mod consts;
mod funcs;
mod types;
