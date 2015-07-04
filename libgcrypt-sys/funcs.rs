extern crate libc;
extern crate libgpg_error_sys;

use libc::{c_void, c_char, c_uchar, c_short, c_ushort, c_int, c_uint, c_long, c_ulong, ssize_t, size_t};

pub use libgpg_error_sys::gpg_err_make as gcry_err_make;
pub use libgpg_error_sys::gpg_err_code as gcry_err_code;
pub use libgpg_error_sys::gpg_err_source as gcry_err_source;
pub use libgpg_error_sys::gpg_strerror as gcry_strerror;
pub use libgpg_error_sys::gpg_strerror_r as gcry_strerror_r;
pub use libgpg_error_sys::gpg_strsource as gcry_strsource;
pub use libgpg_error_sys::gpg_err_code_from_errno as gcry_err_code_from_errno;
pub use libgpg_error_sys::gpg_err_code_to_errno as gcry_err_code_to_errno;
pub use libgpg_error_sys::gpg_err_code_from_syserror as gcry_err_code_from_syserror;
pub use libgpg_error_sys::gpg_err_set_errno as gcry_err_set_errno;
pub use libgpg_error_sys::gpg_err_make_from_errno as gcry_err_make_from_errno;
pub use libgpg_error_sys::gpg_error_from_errno as gcry_error_from_errno;
pub use libgpg_error_sys::gpg_error_from_syserror as gcry_error_from_syserror;

use consts::*;
use types::*;

extern {
    pub fn gcry_check_version(req_version: *const c_char) -> *const c_char;
    pub fn gcry_control(cmd: gcry_ctl_cmds, ...) -> gcry_error_t;

    pub fn gcry_malloc(n: size_t) -> *mut c_void;
    pub fn gcry_calloc(n: size_t, m: size_t) -> *mut c_void;
    pub fn gcry_malloc_secure(n: size_t) -> *mut c_void;
    pub fn gcry_calloc_secure(n: size_t, m: size_t) -> *mut c_void;
    pub fn gcry_realloc(a: *mut c_void, n: size_t) -> *mut c_void;
    pub fn gcry_free(a: *mut c_void);
    pub fn gcry_is_secure(a: *const c_void) -> c_int;

    pub fn gcry_cipher_open(handle: *mut gcry_cipher_hd_t, algo: c_int,
                            mode: c_int, flags: c_uint) -> gcry_error_t;
    pub fn gcry_cipher_close(handle: gcry_cipher_hd_t);
    pub fn gcry_cipher_ctl(handle: gcry_cipher_hd_t, cmd: c_int, buffer: *mut c_void,
                           buflen: size_t) -> gcry_error_t;
    pub fn gcry_cipher_info(handle: gcry_cipher_hd_t, what: c_int, buffer: *mut c_void,
                            nbytes: *mut size_t) -> gcry_error_t;
    pub fn gcry_cipher_algo_info(algo: c_int, what: c_int, buffer: *mut c_void,
                                 nbytes: *mut size_t) -> gcry_error_t;
    pub fn gcry_cipher_algo_name(algo: c_int) -> *const c_char;
    pub fn gcry_cipher_map_name(name: *const c_char) -> c_int;
    pub fn gcry_cipher_mode_from_oid(string: *const c_char) -> c_int;
    pub fn gcry_cipher_get_algo_keylen(algo: c_int) -> size_t;
    pub fn gcry_cipher_get_algo_blklen(algo: c_int) -> size_t;
    pub fn gcry_cipher_encrypt(handle: gcry_cipher_hd_t,
                               output: *mut c_void, outsize: size_t,
                               input: *const c_void, inlen: size_t) -> gcry_error_t;
    pub fn gcry_cipher_decrypt(handle: gcry_cipher_hd_t,
                               output: *mut c_void, outsize: size_t,
                               input: *const c_void, inlen: size_t) -> gcry_error_t;
    pub fn gcry_cipher_setkey(handle: gcry_cipher_hd_t,
                              key: *const c_void, keylen: size_t) -> gcry_error_t;
    pub fn gcry_cipher_setiv(handle: gcry_cipher_hd_t,
                             iv: *const c_void, ivlen: size_t) -> gcry_error_t;
    pub fn gcry_cipher_setctr(handle: gcry_cipher_hd_t,
                              ctr: *const c_void, ctrlen: size_t) -> gcry_error_t;
    pub fn gcry_cipher_authenticate(handle: gcry_cipher_hd_t, abuf: *const c_void,
                                    abuflen: size_t) -> gcry_error_t;
    pub fn gcry_cipher_gettag(handle: gcry_cipher_hd_t, outtag: *mut c_void,
                              taglen: size_t) -> gcry_error_t;
    pub fn gcry_cipher_checktag(handle: gcry_cipher_hd_t, in_tag: *const c_void,
                                taglen: size_t) -> gcry_error_t;

    pub fn gcry_md_open(h: *mut gcry_md_hd_t, algo: c_int, flags: c_uint) -> gcry_error_t;
    pub fn gcry_md_close(h: gcry_md_hd_t);
    pub fn gcry_md_enable(h: gcry_md_hd_t, algo: c_int) -> gcry_error_t;
    pub fn gcry_md_copy(new: *mut gcry_md_hd_t, old: gcry_md_hd_t) -> gcry_error_t;
    pub fn gcry_md_reset(h: gcry_md_hd_t);
    pub fn gcry_md_ctl(h: gcry_md_hd_t, cmd: c_int,
                       buffer: *mut c_void, buflen: size_t) -> gcry_error_t;
    pub fn gcry_md_write(h: gcry_md_hd_t, buffer: *const c_void, length: size_t);
    pub fn gcry_md_read(h: gcry_md_hd_t, algo: c_int) -> *mut u8;
    pub fn gcry_md_hash_buffer(algo: c_int, digest: *mut c_void,
                               buffer: *const c_void, length: size_t);
    pub fn gcry_md_get_algo(h: gcry_md_hd_t) -> c_int;
    pub fn gcry_md_get_algo_dlen(algo: c_int) -> c_uint;
    pub fn gcry_md_is_enabled(a: gcry_md_hd_t, algo: c_int) -> c_int;
    pub fn gcry_md_is_secure(a: gcry_md_hd_t) -> c_int;
    pub fn gcry_md_info(h: gcry_md_hd_t, what: c_int, buffer: *mut c_void,
                        nbytes: *mut size_t) -> gcry_error_t;
    pub fn gcry_md_algo_info(algo: c_int, what: c_int, buffer: *mut c_void,
                             nbytes: *mut size_t) -> gcry_error_t;
    pub fn gcry_md_algo_name(algo: c_int) -> *const c_char;
    pub fn gcry_md_map_name(name: *const c_char) -> c_int;
    pub fn gcry_md_setkey(h: gcry_md_hd_t, key: *const c_void, keylen: size_t) -> gcry_error_t;

    pub fn gcry_mac_open(handle: *mut gcry_mac_hd_t, algo: c_int,
                         flags: c_uint, ctx: gcry_ctx_t) -> gcry_error_t;
    pub fn gcry_mac_close(h: gcry_mac_hd_t);
    pub fn gcry_mac_ctl(h: gcry_mac_hd_t, cmd: c_int, buffer: *mut c_void,
                        buflen: size_t) -> gcry_error_t;
    pub fn gcry_mac_algo_info(algo: c_int, what: c_int, buffer: *mut c_void,
                              nbytes: *mut size_t) -> gcry_error_t;
    pub fn gcry_mac_setkey(h: gcry_mac_hd_t, key: *const c_void,
                           keylen: size_t) -> gcry_error_t;
    pub fn gcry_mac_setiv(h: gcry_mac_hd_t, iv: *const c_void,
                          ivlen: size_t) -> gcry_error_t;
    pub fn gcry_mac_write(h: gcry_mac_hd_t, buffer: *const c_void,
                          length: size_t) -> gcry_error_t;
    pub fn gcry_mac_read(h: gcry_mac_hd_t, buffer: *mut c_void, buflen: *mut size_t) -> gcry_error_t;
    pub fn gcry_mac_verify(h: gcry_mac_hd_t, buffer: *const c_void,
                           buflen: size_t) -> gcry_error_t;
    pub fn gcry_mac_get_algo_maclen(algo: c_int) -> c_uint;
    pub fn gcry_mac_get_algo_keylen(algo: c_int) -> c_uint;
    pub fn gcry_mac_algo_name(algorithm: c_int) -> *const c_char;
    pub fn gcry_mac_map_name(name: *const c_char) -> c_int;

    pub fn gcry_kdf_derive(passphrase: *const c_void, passphraselen: size_t,
                           algo: c_int, subalgo: c_int,
                           salt: *const c_void, saltlen: size_t,
                           iterations: c_ulong,
                           keysize: size_t, keybuffer: *mut c_void) -> gcry_error_t;

    pub fn gcry_randomize(buffer: *mut c_void, length: size_t, level: gcry_random_level_t);
    pub fn gcry_random_add_bytes(buffer: *const c_void, length: size_t,
                                 quality: c_int) -> gcry_error_t;
    pub fn gcry_random_bytes(nbytes: size_t, level: gcry_random_level_t) -> *mut c_void;
    pub fn gcry_random_bytes_secure(nbytes: size_t, level: gcry_random_level_t) -> *mut c_void;
    pub fn gcry_create_nonce(buffer: *mut c_void, length: size_t);

    pub fn gcry_ctx_release(ctx: gcry_ctx_t);
}
