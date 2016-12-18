use ffi;

ffi_enum_wrapper! {
    pub enum Level: ffi::gcry_random_level_t {
        Weak        = ffi::GCRY_WEAK_RANDOM,
        Strong      = ffi::GCRY_STRONG_RANDOM,
        VeryStrong  = ffi::GCRY_VERY_STRONG_RANDOM,
    }
}

#[inline]
pub fn make_nonce(buf: &mut [u8]) {
    let _ = ::get_token();
    unsafe {
        ffi::gcry_create_nonce(buf.as_mut_ptr() as *mut _, buf.len());
    }
}

#[inline]
pub fn randomize(level: Level, buf: &mut [u8]) {
    let _ = ::get_token();
    unsafe {
        ffi::gcry_randomize(buf.as_mut_ptr() as *mut _, buf.len(), level.raw());
    }
}
