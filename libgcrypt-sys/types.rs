use libc::{c_char, c_int, c_uint, c_void, size_t};

pub use libgpg_error_sys::gpg_error_t as gcry_error_t;

// extern {
//     pub type gcry_thread_cbs;
//     pub type gcry_context;
//     pub type gcry_sexp;
//     pub type gcry_mpi;
//     pub type gcry_mpi_point;
//     pub type gcry_cipher_handle;
//     pub type gcry_md_handle;
//     pub type gcry_mac_handle;
// }

#[repr(C)]
pub struct gcry_thread_cbs {
    _priv: [u8; 0],
}
#[repr(C)]
pub struct gcry_context {
    _priv: [u8; 0],
}
#[repr(C)]
pub struct gcry_sexp {
    _priv: [u8; 0],
}
#[repr(C)]
pub struct gcry_mpi {
    _priv: [u8; 0],
}
#[repr(C)]
pub struct gcry_mpi_point {
    _priv: [u8; 0],
}
#[repr(C)]
pub struct gcry_cipher_handle {
    _priv: [u8; 0],
}
#[repr(C)]
pub struct gcry_md_handle {
    _priv: [u8; 0],
}
#[repr(C)]
pub struct gcry_mac_handle {
    _priv: [u8; 0],
}

pub type gcry_ctx_t = *mut gcry_context;
pub type gcry_sexp_t = *mut gcry_sexp;
pub type gcry_mpi_t = *mut gcry_mpi;
pub type gcry_mpi_point_t = *mut gcry_mpi_point;
pub type gcry_cipher_hd_t = *mut gcry_cipher_handle;
pub type gcry_md_hd_t = *mut gcry_md_handle;
pub type gcry_mac_hd_t = *mut gcry_mac_handle;

pub type gcry_prime_check_func_t =
    Option<unsafe extern "C" fn(*mut c_void, c_int, gcry_mpi_t) -> c_int>;

pub type gcry_handler_progress_t =
    Option<unsafe extern "C" fn(*mut c_void, *const c_char, c_int, c_int, c_int)>;
pub type gcry_handler_alloc_t = Option<unsafe extern "C" fn(size_t) -> *mut c_void>;
pub type gcry_handler_secure_check_t = Option<unsafe extern "C" fn(*const c_void) -> c_int>;
pub type gcry_handler_realloc_t = Option<unsafe extern "C" fn(*mut c_void, size_t) -> *mut c_void>;
pub type gcry_handler_free_t = Option<unsafe extern "C" fn(*mut c_void)>;
pub type gcry_handler_no_mem_t = Option<unsafe extern "C" fn(*mut c_void, size_t, c_uint) -> c_int>;
pub type gcry_handler_error_t = Option<unsafe extern "C" fn(*mut c_void, c_int, *const c_char)>;
//pub type gcry_handler_log_t = Option<unsafe extern fn(*mut c_void, c_int, *const c_char, va_list)>
