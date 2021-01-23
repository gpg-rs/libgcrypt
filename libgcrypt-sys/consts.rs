use libc::c_uint;

pub use libgpg_error_sys::gpg_err_code_t as gcry_err_code_t;
pub use libgpg_error_sys::gpg_err_source_t as gcry_err_source_t;

pub mod errors {
    pub use libgpg_error_sys::consts::*;
}

pub use self::errors::*;

pub const GCRY_THREAD_OPTION_DEFAULT: c_uint = 0;
pub const GCRY_THREAD_OPTION_USER: c_uint = 1;
pub const GCRY_THREAD_OPTION_PTH: c_uint = 2;
pub const GCRY_THREAD_OPTION_PTHREAD: c_uint = 3;
pub const GCRY_THREAD_OPTION_VERSION: c_uint = 1;

pub type gcry_ctl_cmds = c_uint;
#[cfg(not(ctest))]
pub const GCRYCTL_SET_KEY: gcry_ctl_cmds = 1;
#[cfg(not(ctest))]
pub const GCRYCTL_SET_IV: gcry_ctl_cmds = 2;
pub const GCRYCTL_CFB_SYNC: gcry_ctl_cmds = 3;
pub const GCRYCTL_RESET: gcry_ctl_cmds = 4;
pub const GCRYCTL_FINALIZE: gcry_ctl_cmds = 5;
pub const GCRYCTL_GET_KEYLEN: gcry_ctl_cmds = 6;
pub const GCRYCTL_GET_BLKLEN: gcry_ctl_cmds = 7;
pub const GCRYCTL_TEST_ALGO: gcry_ctl_cmds = 8;
pub const GCRYCTL_IS_SECURE: gcry_ctl_cmds = 9;
pub const GCRYCTL_GET_ASNOID: gcry_ctl_cmds = 10;
pub const GCRYCTL_ENABLE_ALGO: gcry_ctl_cmds = 11;
pub const GCRYCTL_DISABLE_ALGO: gcry_ctl_cmds = 12;
pub const GCRYCTL_DUMP_RANDOM_STATS: gcry_ctl_cmds = 13;
pub const GCRYCTL_DUMP_SECMEM_STATS: gcry_ctl_cmds = 14;
pub const GCRYCTL_GET_ALGO_NPKEY: gcry_ctl_cmds = 15;
pub const GCRYCTL_GET_ALGO_NSKEY: gcry_ctl_cmds = 16;
pub const GCRYCTL_GET_ALGO_NSIGN: gcry_ctl_cmds = 17;
pub const GCRYCTL_GET_ALGO_NENCR: gcry_ctl_cmds = 18;
pub const GCRYCTL_SET_VERBOSITY: gcry_ctl_cmds = 19;
pub const GCRYCTL_SET_DEBUG_FLAGS: gcry_ctl_cmds = 20;
pub const GCRYCTL_CLEAR_DEBUG_FLAGS: gcry_ctl_cmds = 21;
pub const GCRYCTL_USE_SECURE_RNDPOOL: gcry_ctl_cmds = 22;
pub const GCRYCTL_DUMP_MEMORY_STATS: gcry_ctl_cmds = 23;
pub const GCRYCTL_INIT_SECMEM: gcry_ctl_cmds = 24;
pub const GCRYCTL_TERM_SECMEM: gcry_ctl_cmds = 25;
pub const GCRYCTL_DISABLE_SECMEM_WARN: gcry_ctl_cmds = 27;
pub const GCRYCTL_SUSPEND_SECMEM_WARN: gcry_ctl_cmds = 28;
pub const GCRYCTL_RESUME_SECMEM_WARN: gcry_ctl_cmds = 29;
pub const GCRYCTL_DROP_PRIVS: gcry_ctl_cmds = 30;
pub const GCRYCTL_ENABLE_M_GUARD: gcry_ctl_cmds = 31;
pub const GCRYCTL_START_DUMP: gcry_ctl_cmds = 32;
pub const GCRYCTL_STOP_DUMP: gcry_ctl_cmds = 33;
pub const GCRYCTL_GET_ALGO_USAGE: gcry_ctl_cmds = 34;
pub const GCRYCTL_IS_ALGO_ENABLED: gcry_ctl_cmds = 35;
pub const GCRYCTL_DISABLE_INTERNAL_LOCKING: gcry_ctl_cmds = 36;
pub const GCRYCTL_DISABLE_SECMEM: gcry_ctl_cmds = 37;
pub const GCRYCTL_INITIALIZATION_FINISHED: gcry_ctl_cmds = 38;
pub const GCRYCTL_INITIALIZATION_FINISHED_P: gcry_ctl_cmds = 39;
pub const GCRYCTL_ANY_INITIALIZATION_P: gcry_ctl_cmds = 40;
pub const GCRYCTL_SET_CBC_CTS: gcry_ctl_cmds = 41;
pub const GCRYCTL_SET_CBC_MAC: gcry_ctl_cmds = 42;
#[cfg(not(ctest))]
pub const GCRYCTL_SET_CTR: gcry_ctl_cmds = 43;
pub const GCRYCTL_ENABLE_QUICK_RANDOM: gcry_ctl_cmds = 44;
pub const GCRYCTL_SET_RANDOM_SEED_FILE: gcry_ctl_cmds = 45;
pub const GCRYCTL_UPDATE_RANDOM_SEED_FILE: gcry_ctl_cmds = 46;
pub const GCRYCTL_SET_THREAD_CBS: gcry_ctl_cmds = 47;
pub const GCRYCTL_FAST_POLL: gcry_ctl_cmds = 48;
pub const GCRYCTL_SET_RANDOM_DAEMON_SOCKET: gcry_ctl_cmds = 49;
pub const GCRYCTL_USE_RANDOM_DAEMON: gcry_ctl_cmds = 50;
pub const GCRYCTL_FAKED_RANDOM_P: gcry_ctl_cmds = 51;
pub const GCRYCTL_SET_RNDEGD_SOCKET: gcry_ctl_cmds = 52;
pub const GCRYCTL_PRINT_CONFIG: gcry_ctl_cmds = 53;
pub const GCRYCTL_OPERATIONAL_P: gcry_ctl_cmds = 54;
pub const GCRYCTL_FIPS_MODE_P: gcry_ctl_cmds = 55;
pub const GCRYCTL_FORCE_FIPS_MODE: gcry_ctl_cmds = 56;
pub const GCRYCTL_SELFTEST: gcry_ctl_cmds = 57;
pub const GCRYCTL_DISABLE_HWF: gcry_ctl_cmds = 63;
pub const GCRYCTL_SET_ENFORCED_FIPS_FLAG: gcry_ctl_cmds = 64;
pub const GCRYCTL_SET_PREFERRED_RNG_TYPE: gcry_ctl_cmds = 65;
pub const GCRYCTL_GET_CURRENT_RNG_TYPE: gcry_ctl_cmds = 66;
pub const GCRYCTL_DISABLE_LOCKED_SECMEM: gcry_ctl_cmds = 67;
pub const GCRYCTL_DISABLE_PRIV_DROP: gcry_ctl_cmds = 68;
pub const GCRYCTL_SET_CCM_LENGTHS: gcry_ctl_cmds = 69;
pub const GCRYCTL_CLOSE_RANDOM_DEVICE: gcry_ctl_cmds = 70;
pub const GCRYCTL_INACTIVATE_FIPS_FLAG: gcry_ctl_cmds = 71;
pub const GCRYCTL_REACTIVATE_FIPS_FLAG: gcry_ctl_cmds = 72;
pub const GCRYCTL_SET_SBOX: gcry_ctl_cmds = 73;
pub const GCRYCTL_DRBG_REINIT: gcry_ctl_cmds = 74;
pub const GCRYCTL_SET_TAGLEN: gcry_ctl_cmds = 75;
pub const GCRYCTL_GET_TAGLEN: gcry_ctl_cmds = 76;
pub const GCRYCTL_REINIT_SYSCALL_CLAMP: gcry_ctl_cmds = 77;
pub const GCRYCTL_AUTO_EXPAND_SECMEM: gcry_ctl_cmds = 78;
pub const GCRYCTL_SET_ALLOW_WEAK_KEY: gcry_ctl_cmds = 79;

pub type gcry_sexp_format = c_uint;
pub const GCRYSEXP_FMT_DEFAULT: gcry_sexp_format = 0;
pub const GCRYSEXP_FMT_CANON: gcry_sexp_format = 1;
pub const GCRYSEXP_FMT_BASE64: gcry_sexp_format = 2;
pub const GCRYSEXP_FMT_ADVANCED: gcry_sexp_format = 3;

pub type gcry_mpi_format = c_uint;
pub const GCRYMPI_FMT_NONE: gcry_mpi_format = 0;
pub const GCRYMPI_FMT_STD: gcry_mpi_format = 1;
pub const GCRYMPI_FMT_PGP: gcry_mpi_format = 2;
pub const GCRYMPI_FMT_SSH: gcry_mpi_format = 3;
pub const GCRYMPI_FMT_HEX: gcry_mpi_format = 4;
pub const GCRYMPI_FMT_USG: gcry_mpi_format = 5;
pub const GCRYMPI_FMT_OPAQUE: gcry_mpi_format = 8;

pub type gcry_mpi_flag = c_uint;
pub const GCRYMPI_FLAG_SECURE: gcry_mpi_flag = 1;
pub const GCRYMPI_FLAG_OPAQUE: gcry_mpi_flag = 2;
pub const GCRYMPI_FLAG_IMMUTABLE: gcry_mpi_flag = 4;
pub const GCRYMPI_FLAG_CONST: gcry_mpi_flag = 8;
pub const GCRYMPI_FLAG_USER1: gcry_mpi_flag = 0x0100;
pub const GCRYMPI_FLAG_USER2: gcry_mpi_flag = 0x0200;
pub const GCRYMPI_FLAG_USER3: gcry_mpi_flag = 0x0400;
pub const GCRYMPI_FLAG_USER4: gcry_mpi_flag = 0x0800;

pub type gcry_cipher_algos = c_uint;
pub const GCRY_CIPHER_NONE: gcry_cipher_algos = 0;
pub const GCRY_CIPHER_IDEA: gcry_cipher_algos = 1;
pub const GCRY_CIPHER_3DES: gcry_cipher_algos = 2;
pub const GCRY_CIPHER_CAST5: gcry_cipher_algos = 3;
pub const GCRY_CIPHER_BLOWFISH: gcry_cipher_algos = 4;
pub const GCRY_CIPHER_SAFER_SK128: gcry_cipher_algos = 5;
pub const GCRY_CIPHER_DES_SK: gcry_cipher_algos = 6;
pub const GCRY_CIPHER_AES: gcry_cipher_algos = 7;
pub const GCRY_CIPHER_AES192: gcry_cipher_algos = 8;
pub const GCRY_CIPHER_AES256: gcry_cipher_algos = 9;
pub const GCRY_CIPHER_TWOFISH: gcry_cipher_algos = 10;
pub const GCRY_CIPHER_ARCFOUR: gcry_cipher_algos = 301;
pub const GCRY_CIPHER_DES: gcry_cipher_algos = 302;
pub const GCRY_CIPHER_TWOFISH128: gcry_cipher_algos = 303;
pub const GCRY_CIPHER_SERPENT128: gcry_cipher_algos = 304;
pub const GCRY_CIPHER_SERPENT192: gcry_cipher_algos = 305;
pub const GCRY_CIPHER_SERPENT256: gcry_cipher_algos = 306;
pub const GCRY_CIPHER_RFC2268_40: gcry_cipher_algos = 307;
pub const GCRY_CIPHER_RFC2268_128: gcry_cipher_algos = 308;
pub const GCRY_CIPHER_SEED: gcry_cipher_algos = 309;
pub const GCRY_CIPHER_CAMELLIA128: gcry_cipher_algos = 310;
pub const GCRY_CIPHER_CAMELLIA192: gcry_cipher_algos = 311;
pub const GCRY_CIPHER_CAMELLIA256: gcry_cipher_algos = 312;
pub const GCRY_CIPHER_SALSA20: gcry_cipher_algos = 313;
pub const GCRY_CIPHER_SALSA20R12: gcry_cipher_algos = 314;
pub const GCRY_CIPHER_GOST28147: gcry_cipher_algos = 315;
pub const GCRY_CIPHER_CHACHA20: gcry_cipher_algos = 316;
pub const GCRY_CIPHER_GOST28147_MESH: gcry_cipher_algos = 317;
pub const GCRY_CIPHER_SM4: gcry_cipher_algos = 318;

pub const GCRY_CIPHER_AES128: gcry_cipher_algos = GCRY_CIPHER_AES;
pub const GCRY_CIPHER_RIJNDAEL: gcry_cipher_algos = GCRY_CIPHER_AES;
pub const GCRY_CIPHER_RIJNDAEL128: gcry_cipher_algos = GCRY_CIPHER_AES128;
pub const GCRY_CIPHER_RIJNDAEL192: gcry_cipher_algos = GCRY_CIPHER_AES192;
pub const GCRY_CIPHER_RIJNDAEL256: gcry_cipher_algos = GCRY_CIPHER_AES256;

pub type gcry_cipher_modes = c_uint;
pub const GCRY_CIPHER_MODE_NONE: gcry_cipher_modes = 0;
pub const GCRY_CIPHER_MODE_ECB: gcry_cipher_modes = 1;
pub const GCRY_CIPHER_MODE_CFB: gcry_cipher_modes = 2;
pub const GCRY_CIPHER_MODE_CBC: gcry_cipher_modes = 3;
pub const GCRY_CIPHER_MODE_STREAM: gcry_cipher_modes = 4;
pub const GCRY_CIPHER_MODE_OFB: gcry_cipher_modes = 5;
pub const GCRY_CIPHER_MODE_CTR: gcry_cipher_modes = 6;
pub const GCRY_CIPHER_MODE_AESWRAP: gcry_cipher_modes = 7;
pub const GCRY_CIPHER_MODE_CCM: gcry_cipher_modes = 8;
pub const GCRY_CIPHER_MODE_GCM: gcry_cipher_modes = 9;
pub const GCRY_CIPHER_MODE_POLY1305: gcry_cipher_modes = 10;
pub const GCRY_CIPHER_MODE_OCB: gcry_cipher_modes = 11;
pub const GCRY_CIPHER_MODE_CFB8: gcry_cipher_modes = 12;
pub const GCRY_CIPHER_MODE_XTS: gcry_cipher_modes = 13;
pub const GCRY_CIPHER_MODE_EAX: gcry_cipher_modes = 14;

pub type gcry_cipher_flags = c_uint;
pub const GCRY_CIPHER_SECURE: gcry_cipher_flags = 1;
pub const GCRY_CIPHER_ENABLE_SYNC: gcry_cipher_flags = 2;
pub const GCRY_CIPHER_CBC_CTS: gcry_cipher_flags = 4;
pub const GCRY_CIPHER_CBC_MAC: gcry_cipher_flags = 8;

pub const GCRY_GCM_BLOCK_LEN: c_uint = (128 / 8);
pub const GCRY_CCM_BLOCK_LEN: c_uint = (128 / 8);
pub const GCRY_OCB_BLOCK_LEN: c_uint = (128 / 8);

pub type gcry_pk_algos = c_uint;
pub const GCRY_PK_RSA: gcry_pk_algos = 1;
pub const GCRY_PK_RSA_E: gcry_pk_algos = 2;
pub const GCRY_PK_RSA_S: gcry_pk_algos = 3;
pub const GCRY_PK_ELG_E: gcry_pk_algos = 16;
pub const GCRY_PK_DSA: gcry_pk_algos = 17;
pub const GCRY_PK_ECC: gcry_pk_algos = 18;
pub const GCRY_PK_ELG: gcry_pk_algos = 20;
pub const GCRY_PK_ECDSA: gcry_pk_algos = 301;
pub const GCRY_PK_ECDH: gcry_pk_algos = 302;
pub const GCRY_PK_EDDSA: gcry_pk_algos = 303;

pub const GCRY_PK_USAGE_SIGN: c_uint = 1;
pub const GCRY_PK_USAGE_ENCR: c_uint = 2;
pub const GCRY_PK_USAGE_CERT: c_uint = 4;
pub const GCRY_PK_USAGE_AUTH: c_uint = 8;
pub const GCRY_PK_USAGE_UNKN: c_uint = 128;

pub const GCRY_PK_GET_PUBKEY: c_uint = 1;
pub const GCRY_PK_GET_SECKEY: c_uint = 2;

pub type gcry_ecc_curves = c_uint;
pub const GCRY_ECC_CURVE25519: gcry_ecc_curves = 1;
pub const GCRY_ECC_CURVE448: gcry_ecc_curves = 2;

pub type gcry_md_algos = c_uint;
pub const GCRY_MD_NONE: gcry_md_algos = 0;
pub const GCRY_MD_MD5: gcry_md_algos = 1;
pub const GCRY_MD_SHA1: gcry_md_algos = 2;
pub const GCRY_MD_RMD160: gcry_md_algos = 3;
pub const GCRY_MD_MD2: gcry_md_algos = 5;
pub const GCRY_MD_TIGER: gcry_md_algos = 6;
pub const GCRY_MD_HAVAL: gcry_md_algos = 7;
pub const GCRY_MD_SHA256: gcry_md_algos = 8;
pub const GCRY_MD_SHA384: gcry_md_algos = 9;
pub const GCRY_MD_SHA512: gcry_md_algos = 10;
pub const GCRY_MD_SHA224: gcry_md_algos = 11;
pub const GCRY_MD_MD4: gcry_md_algos = 301;
pub const GCRY_MD_CRC32: gcry_md_algos = 302;
pub const GCRY_MD_CRC32_RFC1510: gcry_md_algos = 303;
pub const GCRY_MD_CRC24_RFC2440: gcry_md_algos = 304;
pub const GCRY_MD_WHIRLPOOL: gcry_md_algos = 305;
pub const GCRY_MD_TIGER1: gcry_md_algos = 306;
pub const GCRY_MD_TIGER2: gcry_md_algos = 307;
pub const GCRY_MD_GOSTR3411_94: gcry_md_algos = 308;
pub const GCRY_MD_STRIBOG256: gcry_md_algos = 309;
pub const GCRY_MD_STRIBOG512: gcry_md_algos = 310;
pub const GCRY_MD_GOSTR3411_CP: gcry_md_algos = 311;
pub const GCRY_MD_SHA3_224: gcry_md_algos = 312;
pub const GCRY_MD_SHA3_256: gcry_md_algos = 313;
pub const GCRY_MD_SHA3_384: gcry_md_algos = 314;
pub const GCRY_MD_SHA3_512: gcry_md_algos = 315;
pub const GCRY_MD_SHAKE128: gcry_md_algos = 316;
pub const GCRY_MD_SHAKE256: gcry_md_algos = 317;
pub const GCRY_MD_BLAKE2B_512: gcry_md_algos = 318;
pub const GCRY_MD_BLAKE2B_384: gcry_md_algos = 319;
pub const GCRY_MD_BLAKE2B_256: gcry_md_algos = 320;
pub const GCRY_MD_BLAKE2B_160: gcry_md_algos = 321;
pub const GCRY_MD_BLAKE2S_256: gcry_md_algos = 322;
pub const GCRY_MD_BLAKE2S_224: gcry_md_algos = 323;
pub const GCRY_MD_BLAKE2S_160: gcry_md_algos = 324;
pub const GCRY_MD_BLAKE2S_128: gcry_md_algos = 325;
pub const GCRY_MD_SM3: gcry_md_algos = 326;
pub const GCRY_MD_SHA512_256: gcry_md_algos = 327;
pub const GCRY_MD_SHA512_224: gcry_md_algos = 328;

pub type gcry_md_flags = c_uint;
pub const GCRY_MD_FLAG_SECURE: gcry_md_flags = 1;
pub const GCRY_MD_FLAG_HMAC: gcry_md_flags = 2;
pub const GCRY_MD_FLAG_BUGEMU1: gcry_md_flags = 0x0100;

pub type gcry_mac_algos = c_uint;
pub const GCRY_MAC_NONE: gcry_mac_algos = 0;
pub const GCRY_MAC_GOST28147_IMIT: gcry_mac_algos = 1;

pub const GCRY_MAC_HMAC_SHA256: gcry_mac_algos = 101;
pub const GCRY_MAC_HMAC_SHA224: gcry_mac_algos = 102;
pub const GCRY_MAC_HMAC_SHA512: gcry_mac_algos = 103;
pub const GCRY_MAC_HMAC_SHA384: gcry_mac_algos = 104;
pub const GCRY_MAC_HMAC_SHA1: gcry_mac_algos = 105;
pub const GCRY_MAC_HMAC_MD5: gcry_mac_algos = 106;
pub const GCRY_MAC_HMAC_MD4: gcry_mac_algos = 107;
pub const GCRY_MAC_HMAC_RMD160: gcry_mac_algos = 108;
pub const GCRY_MAC_HMAC_TIGER1: gcry_mac_algos = 109;
pub const GCRY_MAC_HMAC_WHIRLPOOL: gcry_mac_algos = 110;
pub const GCRY_MAC_HMAC_GOSTR3411_94: gcry_mac_algos = 111;
pub const GCRY_MAC_HMAC_STRIBOG256: gcry_mac_algos = 112;
pub const GCRY_MAC_HMAC_STRIBOG512: gcry_mac_algos = 113;
pub const GCRY_MAC_HMAC_MD2: gcry_mac_algos = 114;
pub const GCRY_MAC_HMAC_SHA3_224: gcry_mac_algos = 115;
pub const GCRY_MAC_HMAC_SHA3_256: gcry_mac_algos = 116;
pub const GCRY_MAC_HMAC_SHA3_384: gcry_mac_algos = 117;
pub const GCRY_MAC_HMAC_SHA3_512: gcry_mac_algos = 118;
pub const GCRY_MAC_HMAC_GOSTR3411_CP: gcry_mac_algos = 119;
pub const GCRY_MAC_HMAC_BLAKE2B_512: gcry_mac_algos = 120;
pub const GCRY_MAC_HMAC_BLAKE2B_384: gcry_mac_algos = 121;
pub const GCRY_MAC_HMAC_BLAKE2B_256: gcry_mac_algos = 122;
pub const GCRY_MAC_HMAC_BLAKE2B_160: gcry_mac_algos = 123;
pub const GCRY_MAC_HMAC_BLAKE2S_256: gcry_mac_algos = 124;
pub const GCRY_MAC_HMAC_BLAKE2S_224: gcry_mac_algos = 125;
pub const GCRY_MAC_HMAC_BLAKE2S_160: gcry_mac_algos = 126;
pub const GCRY_MAC_HMAC_BLAKE2S_128: gcry_mac_algos = 127;
pub const GCRY_MAC_HMAC_SM3: gcry_mac_algos = 128;
pub const GCRY_MAC_HMAC_SHA512_256: gcry_mac_algos = 129;
pub const GCRY_MAC_HMAC_SHA512_224: gcry_mac_algos = 130;

pub const GCRY_MAC_CMAC_AES: gcry_mac_algos = 201;
pub const GCRY_MAC_CMAC_3DES: gcry_mac_algos = 202;
pub const GCRY_MAC_CMAC_CAMELLIA: gcry_mac_algos = 203;
pub const GCRY_MAC_CMAC_CAST5: gcry_mac_algos = 204;
pub const GCRY_MAC_CMAC_BLOWFISH: gcry_mac_algos = 205;
pub const GCRY_MAC_CMAC_TWOFISH: gcry_mac_algos = 206;
pub const GCRY_MAC_CMAC_SERPENT: gcry_mac_algos = 207;
pub const GCRY_MAC_CMAC_SEED: gcry_mac_algos = 208;
pub const GCRY_MAC_CMAC_RFC2268: gcry_mac_algos = 209;
pub const GCRY_MAC_CMAC_IDEA: gcry_mac_algos = 210;
pub const GCRY_MAC_CMAC_GOST28147: gcry_mac_algos = 211;
pub const GCRY_MAC_CMAC_SM4: gcry_mac_algos = 212;

pub const GCRY_MAC_GMAC_AES: gcry_mac_algos = 401;
pub const GCRY_MAC_GMAC_CAMELLIA: gcry_mac_algos = 402;
pub const GCRY_MAC_GMAC_TWOFISH: gcry_mac_algos = 403;
pub const GCRY_MAC_GMAC_SERPENT: gcry_mac_algos = 404;
pub const GCRY_MAC_GMAC_SEED: gcry_mac_algos = 405;

pub const GCRY_MAC_POLY1305: gcry_mac_algos = 501;
pub const GCRY_MAC_POLY1305_AES: gcry_mac_algos = 502;
pub const GCRY_MAC_POLY1305_CAMELLIA: gcry_mac_algos = 503;
pub const GCRY_MAC_POLY1305_TWOFISH: gcry_mac_algos = 504;
pub const GCRY_MAC_POLY1305_SERPENT: gcry_mac_algos = 505;
pub const GCRY_MAC_POLY1305_SEED: gcry_mac_algos = 506;

pub type gcry_mac_flags = c_uint;
pub const GCRY_MAC_FLAG_SECURE: gcry_mac_flags = 1;

pub type gcry_kdf_algos = c_uint;
pub const GCRY_KDF_NONE: gcry_kdf_algos = 0;
pub const GCRY_KDF_SIMPLE_S2K: gcry_kdf_algos = 16;
pub const GCRY_KDF_SALTED_S2K: gcry_kdf_algos = 17;
pub const GCRY_KDF_ITERSALTED_S2K: gcry_kdf_algos = 19;
pub const GCRY_KDF_PBKDF1: gcry_kdf_algos = 33;
pub const GCRY_KDF_PBKDF2: gcry_kdf_algos = 34;
pub const GCRY_KDF_SCRYPT: gcry_kdf_algos = 48;

pub type gcry_random_level = c_uint;
pub type gcry_random_level_t = gcry_random_level;
pub const GCRY_WEAK_RANDOM: gcry_random_level = 0;
pub const GCRY_STRONG_RANDOM: gcry_random_level = 1;
pub const GCRY_VERY_STRONG_RANDOM: gcry_random_level = 2;

pub const GCRY_PRIME_CHECK_AT_FINISH: c_uint = 0;
pub const GCRY_PRIME_CHECK_AT_GOT_PRIME: c_uint = 1;
pub const GCRY_PRIME_CHECK_AT_MAYBE_PRIME: c_uint = 2;

pub const GCRY_PRIME_FLAG_SECRET: c_uint = (1 << 0);
pub const GCRY_PRIME_FLAG_SPECIAL_FACTOR: c_uint = (1 << 1);

pub type gcry_log_levels = c_uint;
pub const GCRY_LOG_CONT: gcry_log_levels = 0;
pub const GCRY_LOG_INFO: gcry_log_levels = 10;
pub const GCRY_LOG_WARN: gcry_log_levels = 20;
pub const GCRY_LOG_ERROR: gcry_log_levels = 30;
pub const GCRY_LOG_FATAL: gcry_log_levels = 40;
pub const GCRY_LOG_BUG: gcry_log_levels = 50;
pub const GCRY_LOG_DEBUG: gcry_log_levels = 100;
