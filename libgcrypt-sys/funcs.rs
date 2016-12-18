extern crate libgpg_error_sys;

use libc::{c_void, c_char, c_uchar, c_int, c_uint, c_ulong, size_t};
use std::ptr;

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
    #[cfg(feature = "shim")]
    pub fn gcry_threads_pthread_shim() -> *mut gcry_thread_cbs;

    pub fn gcry_check_version(req_version: *const c_char) -> *const c_char;
    pub fn gcry_control(cmd: gcry_ctl_cmds, ...) -> gcry_error_t;

    pub fn gcry_sexp_new(retsexp: *mut gcry_sexp_t, buffer: *const c_void,
            length: size_t, autodetect: c_int) -> gcry_error_t;
    pub fn gcry_sexp_create(retsexp: *mut gcry_sexp_t, buffer: *mut c_void, length: size_t,
            autodetect: c_int, freefnc: extern fn(*mut c_void)) -> gcry_error_t;
    pub fn gcry_sexp_sscan(retsexp: *mut gcry_sexp_t, erroff: *mut size_t, buffer: *const c_char,
            length: size_t) -> gcry_error_t;
    pub fn gcry_sexp_build(retsexp: *mut gcry_sexp_t, erroff: *mut size_t,
            format: *const c_char, ...) -> gcry_error_t;
    pub fn gcry_sexp_build_array(retsexp: *mut gcry_sexp_t, erroff: *mut size_t,
            format: *const c_char, arg_list: *mut *mut c_void) -> gcry_error_t;
    pub fn gcry_sexp_release(sexp: gcry_sexp_t);
    pub fn gcry_sexp_canon_len(buffer: *const c_uchar, length: size_t, erroff: *mut size_t,
            errcode: *mut gcry_error_t) -> size_t;
    pub fn gcry_sexp_sprint(sexp: gcry_sexp_t, mode: c_int, buffer: *mut c_void,
            maxlength: size_t) -> size_t;
    pub fn gcry_sexp_dump(a: gcry_sexp_t);
    pub fn gcry_sexp_cons(a: gcry_sexp_t, b: gcry_sexp_t) -> gcry_sexp_t;
    pub fn gcry_sexp_alist(array: *const gcry_sexp_t) -> gcry_sexp_t;
    pub fn gcry_sexp_vlist(a: gcry_sexp_t, ...) -> gcry_sexp_t;
    pub fn gcry_sexp_append(a: gcry_sexp_t, n: gcry_sexp_t) -> gcry_sexp_t;
    pub fn gcry_sexp_prepend(a: gcry_sexp_t, n: gcry_sexp_t) -> gcry_sexp_t;
    pub fn gcry_sexp_find_token(list: gcry_sexp_t, tok: *const c_char,
            toklen: size_t) -> gcry_sexp_t;
    pub fn gcry_sexp_length(list: gcry_sexp_t) -> c_int;
    pub fn gcry_sexp_nth(list: gcry_sexp_t, number: c_int) -> gcry_sexp_t;
    pub fn gcry_sexp_car(list: gcry_sexp_t) -> gcry_sexp_t;
    pub fn gcry_sexp_cdr(list: gcry_sexp_t) -> gcry_sexp_t;
    pub fn gcry_sexp_cadr(list: gcry_sexp_t) -> gcry_sexp_t;
    pub fn gcry_sexp_nth_data(list: gcry_sexp_t, number: c_int,
            datalen: *mut size_t) -> *const c_char;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_sexp_nth_buffer(list: gcry_sexp_t, number: c_int,
            rlength: *mut size_t) -> *mut c_void;
    pub fn gcry_sexp_nth_string(list: gcry_sexp_t, number: c_int) -> *mut c_char;
    pub fn gcry_sexp_nth_mpi(list: gcry_sexp_t, number: c_int, mpifmt: c_int) -> gcry_mpi_t;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_sexp_extract_param(sexp: gcry_sexp_t, path: *const c_char,
            list: *const c_char, ...) -> gcry_error_t;

    pub fn gcry_mpi_new(nbits: c_uint) -> gcry_mpi_t;
    pub fn gcry_mpi_snew(nbits: c_uint) -> gcry_mpi_t;
    pub fn gcry_mpi_release(a: gcry_mpi_t);
    pub fn gcry_mpi_copy(a: gcry_mpi_t) -> gcry_mpi_t;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_snatch(w: gcry_mpi_t, u: gcry_mpi_t);
    pub fn gcry_mpi_set(w: gcry_mpi_t, u: gcry_mpi_t) -> gcry_mpi_t;
    pub fn gcry_mpi_set_ui(w: gcry_mpi_t, u: c_ulong) -> gcry_mpi_t;
    pub fn gcry_mpi_swap(a: gcry_mpi_t, b: gcry_mpi_t);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_is_neg(a: gcry_mpi_t) -> c_int;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_neg(w: gcry_mpi_t, u: gcry_mpi_t);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_abs(w: gcry_mpi_t);
    pub fn gcry_mpi_cmp(u: gcry_mpi_t, v: gcry_mpi_t) -> c_int;
    pub fn gcry_mpi_cmp_ui(u: gcry_mpi_t, v: c_ulong) -> c_int;
    pub fn gcry_mpi_scan(ret_mpi: *mut gcry_mpi_t, format: gcry_mpi_format,
            buffer: *const c_void, buflen: size_t,
            nscanned: *mut size_t) -> gcry_error_t;
    pub fn gcry_mpi_print(format: gcry_mpi_format,
            buffer: *mut c_uchar, buflen: size_t,
            nwritten: *mut size_t,
            a: gcry_mpi_t) -> gcry_error_t;
    pub fn gcry_mpi_aprint(format: gcry_mpi_format, buffer: *mut *mut c_uchar,
            nwritten: *mut size_t, a: gcry_mpi_t) -> gcry_error_t ;
    pub fn gcry_mpi_dump(a: gcry_mpi_t);
    pub fn gcry_mpi_add(w: gcry_mpi_t, u: gcry_mpi_t, v: gcry_mpi_t);
    pub fn gcry_mpi_add_ui(w: gcry_mpi_t, u: gcry_mpi_t, v: c_ulong);
    pub fn gcry_mpi_addm(w: gcry_mpi_t, u: gcry_mpi_t, v: gcry_mpi_t, m: gcry_mpi_t);
    pub fn gcry_mpi_sub(w: gcry_mpi_t, u: gcry_mpi_t, v: gcry_mpi_t);
    pub fn gcry_mpi_sub_ui(w: gcry_mpi_t, u: gcry_mpi_t, v: c_ulong);
    pub fn gcry_mpi_subm(w: gcry_mpi_t, u: gcry_mpi_t, v: gcry_mpi_t, m: gcry_mpi_t);
    pub fn gcry_mpi_mul(w: gcry_mpi_t, u: gcry_mpi_t, v: gcry_mpi_t);
    pub fn gcry_mpi_mul_ui(w: gcry_mpi_t, u: gcry_mpi_t, v: c_ulong);
    pub fn gcry_mpi_mulm(w: gcry_mpi_t, u: gcry_mpi_t, v: gcry_mpi_t, m: gcry_mpi_t);
    pub fn gcry_mpi_mul_2exp(w: gcry_mpi_t, u: gcry_mpi_t, cnt: c_ulong);
    pub fn gcry_mpi_div(q: gcry_mpi_t, r: gcry_mpi_t, dividend: gcry_mpi_t,
            divisor: gcry_mpi_t, round: c_int);
    pub fn gcry_mpi_mod(r: gcry_mpi_t, dividend: gcry_mpi_t, divisor: gcry_mpi_t);
    pub fn gcry_mpi_powm(w: gcry_mpi_t, b: gcry_mpi_t, e: gcry_mpi_t,
            m: gcry_mpi_t);
    pub fn gcry_mpi_gcd(g: gcry_mpi_t, a: gcry_mpi_t, b: gcry_mpi_t) -> c_int;
    pub fn gcry_mpi_invm(x: gcry_mpi_t, a: gcry_mpi_t, m: gcry_mpi_t) -> c_int;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_point_new(nbits: c_uint) -> gcry_mpi_point_t;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_point_release(point: gcry_mpi_point_t);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_point_get(x: gcry_mpi_t, y: gcry_mpi_t, z: gcry_mpi_t,
            point: gcry_mpi_point_t);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_point_snatch_get(x: gcry_mpi_t, y: gcry_mpi_t, z: gcry_mpi_t,
            point: gcry_mpi_point_t);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_point_set(point: gcry_mpi_point_t,
            x: gcry_mpi_t, y: gcry_mpi_t, z: gcry_mpi_t) -> gcry_mpi_point_t;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_point_snatch_set(point: gcry_mpi_point_t,
            x: gcry_mpi_t, y: gcry_mpi_t,
            z: gcry_mpi_t) -> gcry_mpi_point_t;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_ec_new(r_ctx: *mut gcry_ctx_t, keyparam: gcry_sexp_t,
            curvename: *const c_char) -> gcry_error_t;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_ec_get_mpi(name: *const c_char, ctx: gcry_ctx_t, copy: c_int) -> gcry_mpi_t;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_ec_get_point(name: *const c_char, ctx: gcry_ctx_t,
            copy: c_int) -> gcry_mpi_point_t ;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_ec_set_mpi(name: *const c_char, newvalue: gcry_mpi_t,
            ctx: gcry_ctx_t) -> gcry_error_t;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_ec_set_point(name: *const c_char, newvalue: gcry_mpi_point_t,
            ctx: gcry_ctx_t) -> gcry_error_t;
    #[cfg(feature = "v1_7_0")]
    pub fn gcry_mpi_ec_decode_point(result: gcry_mpi_point_t,
            value: gcry_mpi_t, ctx: gcry_ctx_t) -> gcry_error_t;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_ec_get_affine(x: gcry_mpi_t, y: gcry_mpi_t, point: gcry_mpi_point_t,
            ctx: gcry_ctx_t) -> c_int;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_ec_dup(w: gcry_mpi_point_t, u: gcry_mpi_point_t, ctx: gcry_ctx_t);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_ec_add(w: gcry_mpi_point_t, u: gcry_mpi_point_t, v: gcry_mpi_point_t,
            ctx: gcry_ctx_t);
    #[cfg(feature = "v1_7_0")]
    pub fn gcry_mpi_ec_sub(w: gcry_mpi_point_t, u: gcry_mpi_point_t, v: gcry_mpi_point_t,
            ctx: gcry_ctx_t);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_ec_mul(w: gcry_mpi_point_t, n: gcry_mpi_t, u: gcry_mpi_point_t,
            ctx: gcry_ctx_t);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_ec_curve_point(w: gcry_mpi_point_t, ctx: gcry_ctx_t) -> c_int;
    pub fn gcry_mpi_get_nbits(a: gcry_mpi_t) -> c_uint;
    pub fn gcry_mpi_test_bit(a: gcry_mpi_t, n: c_uint) -> c_int;
    pub fn gcry_mpi_set_bit(a: gcry_mpi_t, n: c_uint);
    pub fn gcry_mpi_clear_bit(a: gcry_mpi_t, n: c_uint);
    pub fn gcry_mpi_set_highbit(a: gcry_mpi_t, n: c_uint);
    pub fn gcry_mpi_clear_highbit(a: gcry_mpi_t, n: c_uint);
    pub fn gcry_mpi_rshift(x: gcry_mpi_t, a: gcry_mpi_t, n: c_uint);
    pub fn gcry_mpi_lshift(x: gcry_mpi_t, a: gcry_mpi_t, n: c_uint);
    pub fn gcry_mpi_set_opaque(a: gcry_mpi_t, p: *mut c_void, nbits: c_uint) -> gcry_mpi_t;
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_mpi_set_opaque_copy(a: gcry_mpi_t, p: *const c_void,
            nbits: c_uint) -> gcry_mpi_t;
    pub fn gcry_mpi_get_opaque(a: gcry_mpi_t, nbits: *mut c_uint) -> *mut c_void;
    pub fn gcry_mpi_set_flag(a: gcry_mpi_t, flag: gcry_mpi_flag);
    pub fn gcry_mpi_clear_flag(a: gcry_mpi_t, flag: gcry_mpi_flag);
    pub fn gcry_mpi_get_flag(a: gcry_mpi_t, flag: gcry_mpi_flag) -> c_int;

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

    pub fn gcry_pk_encrypt(result: *mut gcry_sexp_t, data: gcry_sexp_t,
            pkey: gcry_sexp_t) -> gcry_error_t;
    pub fn gcry_pk_decrypt(result: *mut gcry_sexp_t, data: gcry_sexp_t,
            skey: gcry_sexp_t) -> gcry_error_t;
    pub fn gcry_pk_sign(result: *mut gcry_sexp_t, data: gcry_sexp_t,
            skey: gcry_sexp_t) -> gcry_error_t;
    pub fn gcry_pk_verify(sigval: gcry_sexp_t, data: gcry_sexp_t,
            pkey: gcry_sexp_t) -> gcry_error_t;
    pub fn gcry_pk_testkey(key: gcry_sexp_t) -> gcry_error_t;
    pub fn gcry_pk_genkey(r_key: *mut gcry_sexp_t, s_parms: gcry_sexp_t) -> gcry_error_t;
    pub fn gcry_pk_ctl(cmd: c_int, buffer: *mut c_void, buflen: size_t) -> gcry_error_t;
    pub fn gcry_pk_algo_info(algo: c_int, what: c_int,
            buffer: *mut c_void, nbytes: *mut size_t) -> gcry_error_t;
    pub fn gcry_pk_algo_name(algorithm: c_int) -> *const c_char;
    pub fn gcry_pk_map_name(name: *const c_char) -> c_int;
    pub fn gcry_pk_get_nbits(key: gcry_sexp_t) -> c_uint;
    pub fn gcry_pk_get_keygrip(key: gcry_sexp_t, array: *mut c_uchar) -> *mut c_uchar;
    pub fn gcry_pk_get_curve(key: gcry_sexp_t, iterator: c_int,
            r_nbits: *mut c_uint) -> *const c_char;
    pub fn gcry_pk_get_param(algo: c_int, name: *const c_char) -> gcry_sexp_t;
    pub fn gcry_pubkey_get_sexp(r_sexp: *mut gcry_sexp_t, mode: c_int,
            ctx: gcry_ctx_t) -> gcry_error_t;

    pub fn gcry_md_open(h: *mut gcry_md_hd_t, algo: c_int, flags: c_uint) -> gcry_error_t;
    pub fn gcry_md_close(h: gcry_md_hd_t);
    pub fn gcry_md_enable(h: gcry_md_hd_t, algo: c_int) -> gcry_error_t;
    pub fn gcry_md_copy(new: *mut gcry_md_hd_t, old: gcry_md_hd_t) -> gcry_error_t;
    pub fn gcry_md_reset(h: gcry_md_hd_t);
    pub fn gcry_md_ctl(h: gcry_md_hd_t, cmd: c_int,
            buffer: *mut c_void, buflen: size_t) -> gcry_error_t;
    pub fn gcry_md_write(h: gcry_md_hd_t, buffer: *const c_void, length: size_t);
    pub fn gcry_md_read(h: gcry_md_hd_t, algo: c_int) -> *mut u8;
    #[cfg(feature = "v1_7_0")]
    pub fn gcry_md_extract(hd: gcry_md_hd_t, algo: c_int, buffer: *mut c_void,
            length: size_t) -> gcry_error_t;
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
    #[cfg(feature = "v1_7_0")]
    pub fn gcry_mac_get_algo(hd: gcry_mac_hd_t) -> c_int;
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
    pub fn gcry_mpi_randomize(w: gcry_mpi_t, nbits: c_uint, level: gcry_random_level_t);

    pub fn gcry_prime_generate(prime: *mut gcry_mpi_t, prime_bits: c_uint,
            factor_bits: c_uint, factors: *mut *mut gcry_mpi_t,
            cb: gcry_prime_check_func_t, cb_arg: *mut c_void,
            random_level: gcry_random_level_t,
            flags: c_uint) -> gcry_error_t;
    pub fn gcry_prime_group_generator(r_g: *mut gcry_mpi_t, prime: gcry_mpi_t,
            factors: *mut gcry_mpi_t,
            start_g: gcry_mpi_t) -> gcry_error_t;
    pub fn gcry_prime_release_factors(factors: *mut gcry_mpi_t);
    pub fn gcry_prime_check(x: gcry_mpi_t, flags: c_uint) -> gcry_error_t;

    #[cfg(feature = "v1_6_0")]
    pub fn gcry_ctx_release(ctx: gcry_ctx_t);

    #[cfg(feature = "v1_6_0")]
    pub fn gcry_log_debug(fmt: *const c_char, ...);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_log_debughex(text: *const c_char, buffer: *const c_void, length: size_t);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_log_debugmpi(text: *const c_char, mpi: gcry_mpi_t);
    #[cfg(feature = "v1_6_0")]
    pub fn gcry_log_debugpnt(text: *const c_char, point: gcry_mpi_point_t, ctx: gcry_ctx_t);
    pub fn gcry_log_debugsxp(text: *const c_char, sexp: gcry_sexp_t);

    pub fn gcry_set_progress_handler(cb: gcry_handler_progress_t, cb_data: *mut c_void);
    pub fn gcry_set_allocation_handler(func_alloc: gcry_handler_alloc_t,
            func_alloc_secure: gcry_handler_alloc_t,
            func_secure_check: gcry_handler_secure_check_t,
            func_realloc: gcry_handler_realloc_t,
            func_free: gcry_handler_free_t);
    pub fn gcry_set_outofcore_handler(h: gcry_handler_no_mem_t, opaque: *mut c_void);
    pub fn gcry_set_fatalerror_handler(fnc: gcry_handler_error_t, opaque: *mut c_void);
    //pub fn gcry_set_log_handler(f: gcry_handler_log_t, opaque: *mut c_void);

    pub fn gcry_malloc(n: size_t) -> *mut c_void;
    pub fn gcry_calloc(n: size_t, m: size_t) -> *mut c_void;
    pub fn gcry_malloc_secure(n: size_t) -> *mut c_void;
    pub fn gcry_calloc_secure(n: size_t, m: size_t) -> *mut c_void;
    pub fn gcry_realloc(a: *mut c_void, n: size_t) -> *mut c_void;
    pub fn gcry_strdup(string: *const c_char) -> *mut c_char;
    pub fn gcry_xmalloc(n: size_t) -> *mut c_void;
    pub fn gcry_xcalloc(n: size_t, m: size_t) -> *mut c_void;
    pub fn gcry_xmalloc_secure(n: size_t) -> *mut c_void;
    pub fn gcry_xcalloc_secure(n: size_t, m: size_t) -> *mut c_void;
    pub fn gcry_xrealloc(a: *mut c_void, n: size_t) -> *mut c_void;
    pub fn gcry_xstrdup(a: *const c_char) -> *mut c_char;
    pub fn gcry_free(a: *mut c_void);
    pub fn gcry_is_secure(a: *const c_void) -> c_int;
}

#[inline]
pub unsafe fn gcry_fips_mode_active() -> bool {
    gcry_control(GCRYCTL_FIPS_MODE_P, 0) != 0
}
#[inline]
pub unsafe fn gcry_fast_random_poll() -> gcry_error_t {
    gcry_control(GCRYCTL_FAST_POLL, 0)
}

#[inline]
pub unsafe fn gcry_cipher_test_algo(a: c_int) -> gcry_error_t {
    gcry_cipher_algo_info(a, GCRYCTL_TEST_ALGO, ptr::null_mut(), ptr::null_mut())
}
#[inline]
pub unsafe fn gcry_md_test_algo(a: c_int) -> gcry_error_t {
    gcry_md_algo_info(a, GCRYCTL_TEST_ALGO, ptr::null_mut(), ptr::null_mut())
}
#[inline]
pub unsafe fn gcry_mac_test_algo(a: c_int) -> gcry_error_t {
    gcry_mac_algo_info(a, GCRYCTL_TEST_ALGO, ptr::null_mut(), ptr::null_mut())
}
#[inline]
pub unsafe fn gcry_pk_test_algo(a: c_int) -> gcry_error_t {
    gcry_pk_algo_info(a, GCRYCTL_TEST_ALGO, ptr::null_mut(), ptr::null_mut())
}

#[inline]
pub unsafe fn gcry_cipher_reset(h: gcry_cipher_hd_t) -> gcry_error_t {
    gcry_cipher_ctl(h, GCRYCTL_RESET, ptr::null_mut(), 0)
}
#[inline]
pub unsafe fn gcry_cipher_sync(h: gcry_cipher_hd_t) -> gcry_error_t {
    gcry_cipher_ctl(h, GCRYCTL_CFB_SYNC, ptr::null_mut(), 0)
}
#[inline]
pub unsafe fn gcry_cipher_cts(h: gcry_cipher_hd_t, on: bool) -> gcry_error_t {
    gcry_cipher_ctl(h, GCRYCTL_SET_CBC_CTS, ptr::null_mut(), if on { 1 } else { 0 })
}
#[inline]
pub unsafe fn gcry_cipher_set_sbox(h: gcry_cipher_hd_t, oid: *const c_char) -> gcry_error_t {
    gcry_cipher_ctl(h, GCRYCTL_SET_SBOX, oid as *mut _, 0)
}
#[inline]
pub unsafe fn gcry_cipher_final(h: gcry_cipher_hd_t) -> gcry_error_t {
    gcry_cipher_ctl(h, GCRYCTL_FINALIZE, ptr::null_mut(), 0)
}

#[inline]
pub unsafe fn gcry_md_final(h: gcry_md_hd_t) -> gcry_error_t {
    gcry_md_ctl(h, GCRYCTL_FINALIZE, ptr::null_mut(), 0)
}
#[inline]
pub unsafe fn gcry_md_get_asnoid(a: c_int, b: *mut c_void, n: &mut size_t) -> gcry_error_t {
    gcry_md_algo_info(a, GCRYCTL_GET_ASNOID, b, n)
}

#[inline]
pub unsafe fn gcry_mac_reset(h: gcry_mac_hd_t) -> gcry_error_t {
    gcry_mac_ctl(h, GCRYCTL_RESET, ptr::null_mut(), 0)
}
