#![allow(non_upper_case_globals)]
extern crate libgpg_error_sys;

use libc::{c_void, c_char, c_int, c_uint, size_t};

pub use libgpg_error_sys::gpg_error_t as gcry_error_t;

pub enum gcry_thread_cbs {}

pub enum gcry_context {}
pub type gcry_ctx_t = *mut gcry_context;

pub enum gcry_sexp {}
pub type gcry_sexp_t = *mut gcry_sexp;

pub enum gcry_mpi {}
pub type gcry_mpi_t = *mut gcry_mpi;

pub enum gcry_mpi_point {}
pub type gcry_mpi_point_t = *mut gcry_mpi_point;

pub enum gcry_cipher_handle {}
pub type gcry_cipher_hd_t = *mut gcry_cipher_handle;

pub enum gcry_md_handle {}
pub type gcry_md_hd_t = *mut gcry_md_handle;

pub enum gcry_mac_handle {}
pub type gcry_mac_hd_t = *mut gcry_mac_handle;

pub type gcry_prime_check_func_t = Option<extern fn(*mut c_void, c_int, gcry_mpi_t) -> c_int>;

pub type gcry_handler_progress_t = Option<extern fn(*mut c_void, *const c_char, c_int, c_int, c_int)>;
pub type gcry_handler_alloc_t = Option<extern fn(size_t) -> *mut c_void>;
pub type gcry_handler_secure_check_t = Option<extern fn(*const c_void) -> c_int>;
pub type gcry_handler_realloc_t = Option<extern fn(*mut c_void, size_t) -> *mut c_void>;
pub type gcry_handler_free_t = Option<extern fn(*mut c_void)>;
pub type gcry_handler_no_mem_t = Option<extern fn(*mut c_void, size_t, c_uint) -> c_int>;
pub type gcry_handler_error_t = Option<extern fn(*mut c_void, c_int, *const c_char)>;
//pub type gcry_handler_log_t = Option<extern fn(*mut c_void, c_int, *const c_char, va_list)>
