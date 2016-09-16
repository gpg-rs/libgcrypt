use ffi;

enum_wrapper! {
    pub enum Level: ffi::gcry_random_level_t {
        WEAK_RANDOM        = ffi::GCRY_WEAK_RANDOM,
        STRONG_RANDOM      = ffi::GCRY_STRONG_RANDOM,
        VERY_STRONG_RANDOM = ffi::GCRY_VERY_STRONG_RANDOM,
    }
}

pub fn make_nonce(buf: &mut [u8]) {
    let _ = ::get_token();
    unsafe {
        ffi::gcry_create_nonce(buf.as_mut_ptr() as *mut _, buf.len());
    }
}

pub fn randomize(level: Level, buf: &mut [u8]) {
    let _ = ::get_token();
    unsafe {
        ffi::gcry_randomize(buf.as_mut_ptr() as *mut _, buf.len(), level.raw());
    }
}
