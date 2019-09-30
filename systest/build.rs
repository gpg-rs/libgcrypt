use ctest;

use std::env;

fn main() {
    let mut cfg = ctest::TestGenerator::new();
    if let Some(paths) = env::var_os("DEP_GCRYPT_INCLUDE") {
        for p in env::split_paths(&paths) {
            cfg.include(p);
        }
    }
    cfg.header("gcrypt.h");
    cfg.cfg("ctest", None);

    cfg.flag("-Wno-deprecated-declarations");
    cfg.type_name(|s, is_struct| match s {
        "gcry_ctl_cmds" | "gcry_sexp_format" | "gcry_mpi_format" | "gcry_mpi_flag"
        | "gcry_cipher_algos" | "gcry_cipher_modes" | "gcry_cipher_flags" | "gcry_pk_algos"
        | "gcry_md_algos" | "gcry_md_flags" | "gcry_mac_algos" | "gcry_mac_flags"
        | "gcry_kdf_algos" | "gcry_random_level" | "gcry_log_levels" => format!("enum {}", s),
        s if is_struct && !s.ends_with("_t") => format!("struct {}", s),
        s => s.to_string(),
    });
    cfg.skip_struct(|s| match s {
        // Opaque structs
        "gcry_thread_cbs" | "gcry_context" | "gcry_sexp" | "gcry_mpi" | "gcry_mpi_point"
        | "gcry_cipher_handle" | "gcry_md_handle" | "gcry_mac_handle" => true,
        _ => false,
    });
    cfg.skip_signededness(|s| s.ends_with("_t"));

    cfg.generate("../libgcrypt-sys/lib.rs", "all.rs");
}
