#![allow(non_upper_case_globals)]
#![allow(raw_pointer_derive)]
extern crate libc;
extern crate libgpg_error_sys;

use libc::{c_void, c_char, c_uchar, c_short, c_ushort, c_int, c_uint, c_long, c_ulong, ssize_t, size_t};

use consts::*;

pub use libgpg_error_sys::gpg_error_t as gcry_error_t;

#[repr(C)]
pub struct gcry_thread_cbs {
    pub option: c_uint,
}

pub static gcry_threads_pth: gcry_thread_cbs = gcry_thread_cbs {
    option: GCRY_THREAD_OPTION_PTH | (GCRY_THREAD_OPTION_VERSION << 1),
};
pub static gcry_threads_pthread: gcry_thread_cbs = gcry_thread_cbs {
    option: GCRY_THREAD_OPTION_PTHREAD | (GCRY_THREAD_OPTION_VERSION << 1),
};

pub enum gcry_context {}
pub type gcry_ctx_t = *mut gcry_context;

pub enum gcry_sexp {}
pub type gcry_sexp_t = *mut gcry_sexp;

pub enum gcry_cipher_handle {}
pub type gcry_cipher_hd_t = *mut gcry_cipher_handle;

pub enum gcry_md_handle {}
pub type gcry_md_hd_t = *mut gcry_md_handle;

pub enum gcry_mac_handle {}
pub type gcry_mac_hd_t = *mut gcry_mac_handle;
