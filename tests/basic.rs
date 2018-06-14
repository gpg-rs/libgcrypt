extern crate gcrypt;

use gcrypt::cipher::{
    self, Algorithm as CipherAlgorithm, Cipher, Flags as CipherFlags, Mode as CipherMode,
};
use gcrypt::digest::{self, Algorithm as DigestAlgorithm, Flags as DigestFlags, MessageDigest};
use gcrypt::kdf;
use gcrypt::pkey::{self, Algorithm as KeyAlgorithm};
use gcrypt::sexp::{self, SExpression};
use gcrypt::{Error, Gcrypt};

fn setup() -> Gcrypt {
    gcrypt::init(|x| {
        x.disable_secmem().enable_quick_random();
        Ok::<(), ()>(())
    }).unwrap()
}

#[test]
fn test_self_tests() {
    assert_eq!(setup().run_self_tests(), Ok(()));
}

fn check_cipher(algo: CipherAlgorithm, mode: CipherMode, flags: cipher::Flags) {
    let key = b"0123456789abcdef.,;/[]{}-=ABCDEF";
    let mut plain = [0u8; 1040];
    (&mut plain[..16]).copy_from_slice(b"foobar42FOOBAR17");
    for i in 1..(plain.len() / 16) {
        let i = i * 16;
        for j in i..(i + 16) {
            plain[j] = plain[j - 16];
        }
        plain[i + 7] += 1;
        if plain[i + 7] == 0 {
            plain[i + 6] += 1;
        }
        plain[i + 15] += 1;
        if plain[i + 15] == 0 {
            plain[i + 14] += 1;
        }
    }

    let mut cipher = Cipher::with_flags(algo, mode, flags).unwrap();
    cipher.set_key(&key[..algo.key_len()]).unwrap();

    let mut input = [0u8; 1040];
    let mut output = [0u8; 1040];
    cipher.encrypt(&plain, &mut output).unwrap();
    cipher.reset().unwrap();
    cipher.decrypt(&output, &mut input).unwrap();
    assert_eq!(&plain[..], &input[..]);

    cipher.reset().unwrap();
    output.copy_from_slice(&plain);
    cipher.encrypt_inplace(&mut output).unwrap();
    cipher.reset().unwrap();
    cipher.decrypt_inplace(&mut output).unwrap();
    assert_eq!(&plain[..], &output[..]);
}

#[test]
fn test_block_ciphers() {
    let token = setup();

    let algos = [
        CipherAlgorithm::Blowfish,
        CipherAlgorithm::Des,
        CipherAlgorithm::TripleDes,
        CipherAlgorithm::Cast5,
        CipherAlgorithm::Aes128,
        CipherAlgorithm::Aes192,
        CipherAlgorithm::Aes256,
        CipherAlgorithm::Twofish,
        CipherAlgorithm::Twofish128,
        CipherAlgorithm::Serpent128,
        CipherAlgorithm::Serpent192,
        CipherAlgorithm::Serpent256,
        CipherAlgorithm::Rfc2268_40,
        CipherAlgorithm::Seed,
        CipherAlgorithm::Camellia128,
        CipherAlgorithm::Camellia192,
        CipherAlgorithm::Camellia256,
        CipherAlgorithm::Idea,
        CipherAlgorithm::Gost28147,
    ];

    for &algo in algos.iter() {
        if !algo.is_available() {
            continue;
        }

        check_cipher(algo, CipherMode::Ecb, CipherFlags::NONE);
        check_cipher(algo, CipherMode::Cfb, CipherFlags::NONE);
        check_cipher(algo, CipherMode::Ofb, CipherFlags::NONE);
        check_cipher(algo, CipherMode::Cbc, CipherFlags::NONE);
        check_cipher(algo, CipherMode::Cbc, CipherFlags::CBC_CTS);
        check_cipher(algo, CipherMode::Ctr, CipherFlags::NONE);
        if algo.block_len() == 16 && token.check_version("1.6.0") {
            check_cipher(algo, CipherMode::Gcm, CipherFlags::NONE);
        }
    }
}

#[test]
fn test_stream_ciphers() {
    setup();

    let algos = [
        CipherAlgorithm::Arcfour,
        CipherAlgorithm::Salsa20,
        CipherAlgorithm::Salsa20r12,
    ];

    for &algo in algos.iter() {
        if !algo.is_available() {
            continue;
        }

        check_cipher(algo, CipherMode::Stream, CipherFlags::NONE);
    }
}

#[test]
fn test_bulk_cipher_modes() {
    setup();

    let specs: &[(CipherAlgorithm, CipherMode, &[u8], &[u8], [u8; 20])] = &[
        (
            CipherAlgorithm::Aes,
            CipherMode::Cfb,
            b"abcdefghijklmnop",
            b"1234567890123456",
            [
                0x53, 0xda, 0x27, 0x3c, 0x78, 0x3d, 0x54, 0x66, 0x19, 0x63, 0xd7, 0xe6, 0x20, 0x10,
                0xcd, 0xc0, 0x5a, 0x0b, 0x06, 0xcc,
            ],
        ),
        (
            CipherAlgorithm::Aes192,
            CipherMode::Cfb,
            b"abcdefghijklmnopABCDEFG\0",
            b"1234567890123456",
            [
                0xc7, 0xb1, 0xd0, 0x09, 0x95, 0x04, 0x34, 0x61, 0x2b, 0xd9, 0xcb, 0xb3, 0xc7, 0xcb,
                0xef, 0xea, 0x16, 0x19, 0x9b, 0x3e,
            ],
        ),
        (
            CipherAlgorithm::Aes256,
            CipherMode::Cfb,
            b"abcdefghijklmnopABCDEFGHIJKLMNOP",
            b"1234567890123456",
            [
                0x31, 0xe1, 0x1f, 0x63, 0x65, 0x47, 0x8c, 0x3f, 0x53, 0xdb, 0xd9, 0x4d, 0x91, 0x1d,
                0x02, 0x9c, 0x05, 0x25, 0x58, 0x29,
            ],
        ),
        (
            CipherAlgorithm::Aes,
            CipherMode::Cbc,
            b"abcdefghijklmnop",
            b"1234567890123456",
            [
                0xdc, 0x0c, 0xc2, 0xd9, 0x6b, 0x47, 0xf9, 0xeb, 0x06, 0xb4, 0x2f, 0x6e, 0xec, 0x72,
                0xbf, 0x55, 0x26, 0x7f, 0xa9, 0x97,
            ],
        ),
        (
            CipherAlgorithm::Aes192,
            CipherMode::Cbc,
            b"abcdefghijklmnopABCDEFG\0",
            b"1234567890123456",
            [
                0x2b, 0x90, 0x9b, 0xe6, 0x40, 0xab, 0x6e, 0xc2, 0xc5, 0xb1, 0x87, 0xf5, 0x43, 0x84,
                0x7b, 0x04, 0x06, 0x47, 0xd1, 0x8f,
            ],
        ),
        (
            CipherAlgorithm::Aes256,
            CipherMode::Cbc,
            b"abcdefghijklmnopABCDEFGHIJKLMNOP",
            b"1234567890123456",
            [
                0xaa, 0xa8, 0xdf, 0x03, 0xb0, 0xba, 0xc4, 0xe3, 0xc1, 0x02, 0x38, 0x31, 0x8d, 0x86,
                0xcb, 0x49, 0x6d, 0xad, 0xae, 0x01,
            ],
        ),
        (
            CipherAlgorithm::Aes,
            CipherMode::Ofb,
            b"abcdefghijklmnop",
            b"1234567890123456",
            [
                0x65, 0xfe, 0xde, 0x48, 0xd0, 0xa1, 0xa6, 0xf9, 0x24, 0x6b, 0x52, 0x5f, 0x21, 0x8a,
                0x6f, 0xc7, 0x70, 0x3b, 0xd8, 0x4a,
            ],
        ),
        (
            CipherAlgorithm::Aes192,
            CipherMode::Ofb,
            b"abcdefghijklmnopABCDEFG\0",
            b"1234567890123456",
            [
                0x59, 0x5b, 0x02, 0xa2, 0x88, 0xc0, 0xbe, 0x94, 0x43, 0xaa, 0x39, 0xf6, 0xbd, 0xcc,
                0x83, 0x99, 0xee, 0x00, 0xa1, 0x91,
            ],
        ),
        (
            CipherAlgorithm::Aes256,
            CipherMode::Ofb,
            b"abcdefghijklmnopABCDEFGHIJKLMNOP",
            b"1234567890123456",
            [
                0x38, 0x8c, 0xe1, 0xe2, 0xbe, 0x67, 0x60, 0xe8, 0xeb, 0xce, 0xd0, 0xc6, 0xaa, 0xd6,
                0xf6, 0x26, 0x15, 0x56, 0xd0, 0x2b,
            ],
        ),
        (
            CipherAlgorithm::Aes,
            CipherMode::Ctr,
            b"abcdefghijklmnop",
            b"1234567890123456",
            [
                0x9a, 0x48, 0x94, 0xd6, 0x50, 0x46, 0x81, 0xdb, 0x68, 0x34, 0x3b, 0xc5, 0x9e, 0x66,
                0x94, 0x81, 0x98, 0xa0, 0xf9, 0xff,
            ],
        ),
        (
            CipherAlgorithm::Aes192,
            CipherMode::Ctr,
            b"abcdefghijklmnopABCDEFG\0",
            b"1234567890123456",
            [
                0x2c, 0x2c, 0xd3, 0x75, 0x81, 0x2a, 0x59, 0x07, 0xeb, 0x08, 0xce, 0x28, 0x4c, 0x0c,
                0x6a, 0xa8, 0x8f, 0xa3, 0x98, 0x7e,
            ],
        ),
        (
            CipherAlgorithm::Aes256,
            CipherMode::Ctr,
            b"abcdefghijklmnopABCDEFGHIJKLMNOP",
            b"1234567890123456",
            [
                0x64, 0xce, 0x73, 0x03, 0xc7, 0x89, 0x99, 0x1f, 0xf1, 0xce, 0xfe, 0xfb, 0xb9, 0x42,
                0x30, 0xdf, 0xbb, 0x68, 0x6f, 0xd3,
            ],
        ),
        (
            CipherAlgorithm::Aes,
            CipherMode::Ecb,
            b"abcdefghijklmnop",
            b"1234567890123456",
            [
                0x51, 0xae, 0xf5, 0xac, 0x22, 0xa0, 0xba, 0x11, 0xc5, 0xaa, 0xb4, 0x70, 0x99, 0xce,
                0x18, 0x08, 0x12, 0x9b, 0xb1, 0xc5,
            ],
        ),
        (
            CipherAlgorithm::Aes192,
            CipherMode::Ecb,
            b"abcdefghijklmnopABCDEFG\0",
            b"1234567890123456",
            [
                0x57, 0x91, 0xea, 0x48, 0xd8, 0xbf, 0x9e, 0xc1, 0xae, 0x33, 0xb3, 0xfd, 0xf7, 0x7a,
                0xeb, 0x30, 0xb1, 0x62, 0x0d, 0x82,
            ],
        ),
        (
            CipherAlgorithm::Aes256,
            CipherMode::Ecb,
            b"abcdefghijklmnopABCDEFGHIJKLMNOP",
            b"1234567890123456",
            [
                0x2d, 0x71, 0x54, 0xb9, 0xc5, 0x28, 0x76, 0xff, 0x76, 0xb5, 0x99, 0x37, 0x99, 0x9d,
                0xf7, 0x10, 0x6d, 0x86, 0x4f, 0x3f,
            ],
        ),
    ];

    let mut buffer = vec![0u8; 1600];
    let mut output = vec![0u8; 1600];
    for spec in specs {
        for (i, b) in buffer.iter_mut().enumerate() {
            *b = ((i & 0xff) ^ ((i >> 8) & 0xff)) as u8;
        }

        let mut hde = Cipher::new(spec.0, spec.1).unwrap();
        let mut hdd = Cipher::new(spec.0, spec.1).unwrap();
        hde.set_key(spec.2).unwrap();
        hdd.set_key(spec.2).unwrap();
        hde.set_iv(spec.3).unwrap();
        hdd.set_iv(spec.3).unwrap();
        hde.encrypt(&buffer, &mut output).unwrap();

        let mut digest = MessageDigest::new(DigestAlgorithm::Sha1).unwrap();
        digest.update(&output);
        assert_eq!(&spec.4, digest.get_only_digest().unwrap());
        hdd.decrypt_inplace(&mut output).unwrap();
        assert_eq!(&buffer, &output);
    }
}

fn check_digest(algo: DigestAlgorithm, data: &[u8], expected: &[u8]) {
    let mut digest = MessageDigest::new(algo).unwrap();
    if data.starts_with(b"!") && data.len() == 1 {
        let aaa = [b'a'; 1000];
        for _ in 0..1000 {
            digest.update(&aaa);
        }
    } else {
        digest.update(data);
    }
    assert_eq!(Some(expected), digest.get_only_digest());
}

#[test]
fn test_digests() {
    setup();

    let specs: &[(DigestAlgorithm, &[u8], &[u8])] = &[
        (
            DigestAlgorithm::Md4,
            b"",
            b"\x31\xD6\xCF\xE0\xD1\x6A\xE9\x31\xB7\x3C\x59\xD7\xE0\xC0\x89\xC0",
        ),
        (
            DigestAlgorithm::Md4,
            b"a",
            b"\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24",
        ),
        (
            DigestAlgorithm::Md4,
            b"message digest",
            b"\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b",
        ),
        (
            DigestAlgorithm::Md5,
            b"",
            b"\xD4\x1D\x8C\xD9\x8F\x00\xB2\x04\xE9\x80\x09\x98\xEC\xF8\x42\x7E",
        ),
        (
            DigestAlgorithm::Md5,
            b"a",
            b"\x0C\xC1\x75\xB9\xC0\xF1\xB6\xA8\x31\xC3\x99\xE2\x69\x77\x26\x61",
        ),
        (
            DigestAlgorithm::Md5,
            b"abc",
            b"\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72",
        ),
        (
            DigestAlgorithm::Md5,
            b"message digest",
            b"\xF9\x6B\x69\x7D\x7C\xB7\x93\x8D\x52\x5A\x2F\x31\xAA\xF1\x61\xD0",
        ),
        (
            DigestAlgorithm::Sha1,
            b"abc",
            b"\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D",
        ),
        (
            DigestAlgorithm::Sha1,
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            b"\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1",
        ),
        (
            DigestAlgorithm::Sha1,
            b"!", /* kludge for b"a"*1000000 */
            b"\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F",
        ),
        (
            DigestAlgorithm::Sha224,
            b"abc",
            b"\x23\x09\x7d\x22\x34\x05\xd8\x22\x86\x42\xa4\x77\xbd\xa2\
           \x55\xb3\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7\xe3\x6c\x9d\xa7",
        ),
        (
            DigestAlgorithm::Sha224,
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            b"\x75\x38\x8b\x16\x51\x27\x76\xcc\x5d\xba\x5d\xa1\xfd\x89\
           \x01\x50\xb0\xc6\x45\x5c\xb4\xf5\x8b\x19\x52\x52\x25\x25",
        ),
        (
            DigestAlgorithm::Sha224,
            b"!",
            b"\x20\x79\x46\x55\x98\x0c\x91\xd8\xbb\xb4\xc1\xea\x97\x61\
           \x8a\x4b\xf0\x3f\x42\x58\x19\x48\xb2\xee\x4e\xe7\xad\x67",
        ),
        (
            DigestAlgorithm::Sha256,
            b"abc",
            b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\
           \xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad",
        ),
        (
            DigestAlgorithm::Sha256,
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            b"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\
           \xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1",
        ),
        (
            DigestAlgorithm::Sha256,
            b"!",
            b"\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67\
           \xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0",
        ),
        (
            DigestAlgorithm::Sha384,
            b"abc",
            b"\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07\
           \x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed\
           \x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7",
        ),
        (
            DigestAlgorithm::Sha512,
            b"abc",
            b"\xDD\xAF\x35\xA1\x93\x61\x7A\xBA\xCC\x41\x73\x49\xAE\x20\x41\x31\
           \x12\xE6\xFA\x4E\x89\xA9\x7E\xA2\x0A\x9E\xEE\xE6\x4B\x55\xD3\x9A\
           \x21\x92\x99\x2A\x27\x4F\xC1\xA8\x36\xBA\x3C\x23\xA3\xFE\xEB\xBD\
           \x45\x4D\x44\x23\x64\x3C\xE8\x0E\x2A\x9A\xC9\x4F\xA5\x4C\xA4\x9F",
        ),
        (
            DigestAlgorithm::Rmd160,
            b"",
            b"\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28\x08\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31",
        ),
        (
            DigestAlgorithm::Rmd160,
            b"a",
            b"\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae\x34\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe",
        ),
        (
            DigestAlgorithm::Rmd160,
            b"abc",
            b"\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc",
        ),
        (
            DigestAlgorithm::Rmd160,
            b"message digest",
            b"\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8\x81\xb1\x23\xa8\x5f\xfa\x21\x59\x5f\x36",
        ),
        (DigestAlgorithm::Crc32, b"", b"\x00\x00\x00\x00"),
        (DigestAlgorithm::Crc32, b"foo", b"\x8c\x73\x65\x21"),
        (DigestAlgorithm::Crc32Rfc1510, b"", b"\x00\x00\x00\x00"),
        (DigestAlgorithm::Crc32Rfc1510, b"foo", b"\x73\x32\xbc\x33"),
        (
            DigestAlgorithm::Crc32Rfc1510,
            b"test0123456789",
            b"\xb8\x3e\x88\xd6",
        ),
        (
            DigestAlgorithm::Crc32Rfc1510,
            b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
            b"\xe3\x41\x80\xf7",
        ),
        (DigestAlgorithm::Crc32Rfc1510, b"\x80", b"\xed\xb8\x83\x20"),
        (DigestAlgorithm::Crc24Rfc2440, b"", b"\xb7\x04\xce"),
        (DigestAlgorithm::Crc24Rfc2440, b"foo", b"\x4f\xc2\x55"),
        (
            DigestAlgorithm::Tiger,
            b"",
            b"\x24\xF0\x13\x0C\x63\xAC\x93\x32\x16\x16\x6E\x76\xB1\xBB\x92\x5F\
           \xF3\x73\xDE\x2D\x49\x58\x4E\x7A",
        ),
        (
            DigestAlgorithm::Tiger,
            b"abc",
            b"\xF2\x58\xC1\xE8\x84\x14\xAB\x2A\x52\x7A\xB5\x41\xFF\xC5\xB8\xBF\
           \x93\x5F\x7B\x95\x1C\x13\x29\x51",
        ),
        (
            DigestAlgorithm::Tiger,
            b"Tiger",
            b"\x9F\x00\xF5\x99\x07\x23\x00\xDD\x27\x6A\xBB\x38\xC8\xEB\x6D\xEC\
           \x37\x79\x0C\x11\x6F\x9D\x2B\xDF",
        ),
        (
            DigestAlgorithm::Tiger,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
            b"\x87\xFB\x2A\x90\x83\x85\x1C\xF7\x47\x0D\x2C\xF8\x10\xE6\xDF\x9E\
           \xB5\x86\x44\x50\x34\xA5\xA3\x86",
        ),
        (
            DigestAlgorithm::Tiger,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789",
            b"\x46\x7D\xB8\x08\x63\xEB\xCE\x48\x8D\xF1\xCD\x12\x61\x65\x5D\xE9\
           \x57\x89\x65\x65\x97\x5F\x91\x97",
        ),
        (
            DigestAlgorithm::Tiger,
            b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham",
            b"\x0C\x41\x0A\x04\x29\x68\x86\x8A\x16\x71\xDA\x5A\x3F\xD2\x9A\x72\
           \x5E\xC1\xE4\x57\xD3\xCD\xB3\x03",
        ),
        (
            DigestAlgorithm::Tiger,
            b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of \
           Fast Software Encryption 3, Cambridge.",
            b"\xEB\xF5\x91\xD5\xAF\xA6\x55\xCE\x7F\x22\x89\x4F\xF8\x7F\x54\xAC\
           \x89\xC8\x11\xB6\xB0\xDA\x31\x93",
        ),
        (
            DigestAlgorithm::Tiger,
            b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of \
           Fast Software Encryption 3, Cambridge, 1996.",
            b"\x3D\x9A\xEB\x03\xD1\xBD\x1A\x63\x57\xB2\x77\x4D\xFD\x6D\x5B\x24\
           \xDD\x68\x15\x1D\x50\x39\x74\xFC",
        ),
        (
            DigestAlgorithm::Tiger,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-\
           ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
            b"\x00\xB8\x3E\xB4\xE5\x34\x40\xC5\x76\xAC\x6A\xAE\xE0\xA7\x48\x58\
           \x25\xFD\x15\xE7\x0A\x59\xFF\xE4",
        ),
        (
            DigestAlgorithm::Tiger1,
            b"",
            b"\x32\x93\xAC\x63\x0C\x13\xF0\x24\x5F\x92\xBB\xB1\x76\x6E\x16\x16\
           \x7A\x4E\x58\x49\x2D\xDE\x73\xF3",
        ),
        (
            DigestAlgorithm::Tiger1,
            b"a",
            b"\x77\xBE\xFB\xEF\x2E\x7E\xF8\xAB\x2E\xC8\xF9\x3B\xF5\x87\xA7\xFC\
           \x61\x3E\x24\x7F\x5F\x24\x78\x09",
        ),
        (
            DigestAlgorithm::Tiger1,
            b"abc",
            b"\x2A\xAB\x14\x84\xE8\xC1\x58\xF2\xBF\xB8\xC5\xFF\x41\xB5\x7A\x52\
           \x51\x29\x13\x1C\x95\x7B\x5F\x93",
        ),
        (
            DigestAlgorithm::Tiger1,
            b"message digest",
            b"\xD9\x81\xF8\xCB\x78\x20\x1A\x95\x0D\xCF\x30\x48\x75\x1E\x44\x1C\
           \x51\x7F\xCA\x1A\xA5\x5A\x29\xF6",
        ),
        (
            DigestAlgorithm::Tiger1,
            b"abcdefghijklmnopqrstuvwxyz",
            b"\x17\x14\xA4\x72\xEE\xE5\x7D\x30\x04\x04\x12\xBF\xCC\x55\x03\x2A\
           \x0B\x11\x60\x2F\xF3\x7B\xEE\xE9",
        ),
        (
            DigestAlgorithm::Tiger1,
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            b"\x0F\x7B\xF9\xA1\x9B\x9C\x58\xF2\xB7\x61\x0D\xF7\xE8\x4F\x0A\xC3\
           \xA7\x1C\x63\x1E\x7B\x53\xF7\x8E",
        ),
        (
            DigestAlgorithm::Tiger1,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            b"\x8D\xCE\xA6\x80\xA1\x75\x83\xEE\x50\x2B\xA3\x8A\x3C\x36\x86\x51\
           \x89\x0F\xFB\xCC\xDC\x49\xA8\xCC",
        ),
        (
            DigestAlgorithm::Tiger1,
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            b"\x1C\x14\x79\x55\x29\xFD\x9F\x20\x7A\x95\x8F\x84\xC5\x2F\x11\xE8\
           \x87\xFA\x0C\xAB\xDF\xD9\x1B\xFD",
        ),
        (
            DigestAlgorithm::Tiger1,
            b"!",
            b"\x6D\xB0\xE2\x72\x9C\xBE\xAD\x93\xD7\x15\xC6\xA7\xD3\x63\x02\xE9\
           \xB3\xCE\xE0\xD2\xBC\x31\x4B\x41",
        ),
        (
            DigestAlgorithm::Tiger2,
            b"",
            b"\x44\x41\xBE\x75\xF6\x01\x87\x73\xC2\x06\xC2\x27\x45\x37\x4B\x92\
           \x4A\xA8\x31\x3F\xEF\x91\x9F\x41",
        ),
        (
            DigestAlgorithm::Tiger2,
            b"a",
            b"\x67\xE6\xAE\x8E\x9E\x96\x89\x99\xF7\x0A\x23\xE7\x2A\xEA\xA9\x25\
           \x1C\xBC\x7C\x78\xA7\x91\x66\x36",
        ),
        (
            DigestAlgorithm::Tiger2,
            b"abc",
            b"\xF6\x8D\x7B\xC5\xAF\x4B\x43\xA0\x6E\x04\x8D\x78\x29\x56\x0D\x4A\
           \x94\x15\x65\x8B\xB0\xB1\xF3\xBF",
        ),
        (
            DigestAlgorithm::Tiger2,
            b"message digest",
            b"\xE2\x94\x19\xA1\xB5\xFA\x25\x9D\xE8\x00\x5E\x7D\xE7\x50\x78\xEA\
           \x81\xA5\x42\xEF\x25\x52\x46\x2D",
        ),
        (
            DigestAlgorithm::Tiger2,
            b"abcdefghijklmnopqrstuvwxyz",
            b"\xF5\xB6\xB6\xA7\x8C\x40\x5C\x85\x47\xE9\x1C\xD8\x62\x4C\xB8\xBE\
           \x83\xFC\x80\x4A\x47\x44\x88\xFD",
        ),
        (
            DigestAlgorithm::Tiger2,
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            b"\xA6\x73\x7F\x39\x97\xE8\xFB\xB6\x3D\x20\xD2\xDF\x88\xF8\x63\x76\
           \xB5\xFE\x2D\x5C\xE3\x66\x46\xA9",
        ),
        (
            DigestAlgorithm::Tiger2,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            b"\xEA\x9A\xB6\x22\x8C\xEE\x7B\x51\xB7\x75\x44\xFC\xA6\x06\x6C\x8C\
           \xBB\x5B\xBA\xE6\x31\x95\x05\xCD",
        ),
        (
            DigestAlgorithm::Tiger2,
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            b"\xD8\x52\x78\x11\x53\x29\xEB\xAA\x0E\xEC\x85\xEC\xDC\x53\x96\xFD\
           \xA8\xAA\x3A\x58\x20\x94\x2F\xFF",
        ),
        (
            DigestAlgorithm::Tiger2,
            b"!",
            b"\xE0\x68\x28\x1F\x06\x0F\x55\x16\x28\xCC\x57\x15\xB9\xD0\x22\x67\
           \x96\x91\x4D\x45\xF7\x71\x7C\xF4",
        ),
        (
            DigestAlgorithm::Whirlpool,
            b"",
            b"\x19\xFA\x61\xD7\x55\x22\xA4\x66\x9B\x44\xE3\x9C\x1D\x2E\x17\x26\
           \xC5\x30\x23\x21\x30\xD4\x07\xF8\x9A\xFE\xE0\x96\x49\x97\xF7\xA7\
           \x3E\x83\xBE\x69\x8B\x28\x8F\xEB\xCF\x88\xE3\xE0\x3C\x4F\x07\x57\
           \xEA\x89\x64\xE5\x9B\x63\xD9\x37\x08\xB1\x38\xCC\x42\xA6\x6E\xB3",
        ),
        (
            DigestAlgorithm::Whirlpool,
            b"a",
            b"\x8A\xCA\x26\x02\x79\x2A\xEC\x6F\x11\xA6\x72\x06\x53\x1F\xB7\xD7\
           \xF0\xDF\xF5\x94\x13\x14\x5E\x69\x73\xC4\x50\x01\xD0\x08\x7B\x42\
           \xD1\x1B\xC6\x45\x41\x3A\xEF\xF6\x3A\x42\x39\x1A\x39\x14\x5A\x59\
           \x1A\x92\x20\x0D\x56\x01\x95\xE5\x3B\x47\x85\x84\xFD\xAE\x23\x1A",
        ),
        (
            DigestAlgorithm::Whirlpool,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            b"\xDC\x37\xE0\x08\xCF\x9E\xE6\x9B\xF1\x1F\x00\xED\x9A\xBA\x26\x90\
           \x1D\xD7\xC2\x8C\xDE\xC0\x66\xCC\x6A\xF4\x2E\x40\xF8\x2F\x3A\x1E\
           \x08\xEB\xA2\x66\x29\x12\x9D\x8F\xB7\xCB\x57\x21\x1B\x92\x81\xA6\
           \x55\x17\xCC\x87\x9D\x7B\x96\x21\x42\xC6\x5F\x5A\x7A\xF0\x14\x67",
        ),
        (
            DigestAlgorithm::Whirlpool,
            b"!",
            b"\x0C\x99\x00\x5B\xEB\x57\xEF\xF5\x0A\x7C\xF0\x05\x56\x0D\xDF\x5D\
           \x29\x05\x7F\xD8\x6B\x20\xBF\xD6\x2D\xEC\xA0\xF1\xCC\xEA\x4A\xF5\
           \x1F\xC1\x54\x90\xED\xDC\x47\xAF\x32\xBB\x2B\x66\xC3\x4F\xF9\xAD\
           \x8C\x60\x08\xAD\x67\x7F\x77\x12\x69\x53\xB2\x26\xE4\xED\x8B\x01",
        ),
        (
            DigestAlgorithm::GostR3411_94,
            b"This is message, length=32 bytes",
            b"\xB1\xC4\x66\xD3\x75\x19\xB8\x2E\x83\x19\x81\x9F\xF3\x25\x95\xE0\
           \x47\xA2\x8C\xB6\xF8\x3E\xFF\x1C\x69\x16\xA8\x15\xA6\x37\xFF\xFA",
        ),
        (
            DigestAlgorithm::GostR3411_94,
            b"Suppose the original message has length = 50 bytes",
            b"\x47\x1A\xBA\x57\xA6\x0A\x77\x0D\x3A\x76\x13\x06\x35\xC1\xFB\xEA\
           \x4E\xF1\x4D\xE5\x1F\x78\xB4\xAE\x57\xDD\x89\x3B\x62\xF5\x52\x08",
        ),
        (
            DigestAlgorithm::GostR3411_94,
            b"",
            b"\xCE\x85\xB9\x9C\xC4\x67\x52\xFF\xFE\xE3\x5C\xAB\x9A\x7B\x02\x78\
           \xAB\xB4\xC2\xD2\x05\x5C\xFF\x68\x5A\xF4\x91\x2C\x49\x49\x0F\x8D",
        ),
        (
            DigestAlgorithm::GostR3411_94,
            b"!",
            b"\x5C\x00\xCC\xC2\x73\x4C\xDD\x33\x32\xD3\xD4\x74\x95\x76\xE3\xC1\
           \xA7\xDB\xAF\x0E\x7E\xA7\x4E\x9F\xA6\x02\x41\x3C\x90\xA1\x29\xFA",
        ),
        (
            DigestAlgorithm::Stribog512,
            b"012345678901234567890123456789012345678901234567890123456789012",
            b"\x1b\x54\xd0\x1a\x4a\xf5\xb9\xd5\xcc\x3d\x86\xd6\x8d\x28\x54\x62\
           \xb1\x9a\xbc\x24\x75\x22\x2f\x35\xc0\x85\x12\x2b\xe4\xba\x1f\xfa\
           \x00\xad\x30\xf8\x76\x7b\x3a\x82\x38\x4c\x65\x74\xf0\x24\xc3\x11\
           \xe2\xa4\x81\x33\x2b\x08\xef\x7f\x41\x79\x78\x91\xc1\x64\x6f\x48",
        ),
        (
            DigestAlgorithm::Stribog256,
            b"012345678901234567890123456789012345678901234567890123456789012",
            b"\x9d\x15\x1e\xef\xd8\x59\x0b\x89\xda\xa6\xba\x6c\xb7\x4a\xf9\x27\
           \x5d\xd0\x51\x02\x6b\xb1\x49\xa4\x52\xfd\x84\xe5\xe5\x7b\x55\x00",
        ),
        (
            DigestAlgorithm::Stribog512,
            b"\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee\xe6\xe8\
           \x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20\xf1\x20\xec\xee\
           \xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20\xed\xe0\x20\xf5\xf0\xe0\
           \xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
            b"\x1e\x88\xe6\x22\x26\xbf\xca\x6f\x99\x94\xf1\xf2\xd5\x15\x69\xe0\
           \xda\xf8\x47\x5a\x3b\x0f\xe6\x1a\x53\x00\xee\xe4\x6d\x96\x13\x76\
           \x03\x5f\xe8\x35\x49\xad\xa2\xb8\x62\x0f\xcd\x7c\x49\x6c\xe5\xb3\
           \x3f\x0c\xb9\xdd\xdc\x2b\x64\x60\x14\x3b\x03\xda\xba\xc9\xfb\x28",
        ),
        (
            DigestAlgorithm::Stribog256,
            b"\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee\xe6\xe8\
           \x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20\xf1\x20\xec\xee\
           \xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20\xed\xe0\x20\xf5\xf0\xe0\
           \xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
            b"\x9d\xd2\xfe\x4e\x90\x40\x9e\x5d\xa8\x7f\x53\x97\x6d\x74\x05\xb0\
           \xc0\xca\xc6\x28\xfc\x66\x9a\x74\x1d\x50\x06\x3c\x55\x7e\x8f\x50",
        ),
    ];

    for spec in specs {
        if !spec.0.is_available() {
            continue;
        }

        check_digest(spec.0, spec.1, spec.2);
    }
}

fn check_hmac(algo: DigestAlgorithm, data: &[u8], key: &[u8], expected: &[u8]) {
    let mut hmac = MessageDigest::with_flags(algo, DigestFlags::HMAC).unwrap();
    hmac.set_key(key).unwrap();
    hmac.update(data);
    assert_eq!(Some(expected), hmac.get_only_digest());
}

#[test]
fn test_hmacs() {
    setup();

    let specs: &[(DigestAlgorithm, &[u8], &[u8], &[u8])] = &[
        (
            DigestAlgorithm::Md5,
            b"what do ya want for nothing?",
            b"Jefe",
            b"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38",
        ),
        (
            DigestAlgorithm::Md5,
            b"Hi There",
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            b"\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d",
        ),
        (
            DigestAlgorithm::Md5,
            b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd",
            b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
            b"\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6",
        ),
        (
            DigestAlgorithm::Md5,
            b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd",
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
           \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
            b"\x69\x7e\xaf\x0a\xca\x3a\x3a\xea\x3a\x75\x16\x47\x46\xff\xaa\x79",
        ),
        (
            DigestAlgorithm::Md5,
            b"Test With Truncation",
            b"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
            b"\x56\x46\x1e\xf2\x34\x2e\xdc\x00\xf9\xba\xb9\x95\x69\x0e\xfd\x4c",
        ),
        (
            DigestAlgorithm::Md5,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa",
            b"\x6b\x1a\xb7\xfe\x4b\xd7\xbf\x8f\x0b\x62\xe6\xce\x61\xb9\xd0\xcd",
        ),
        (
            DigestAlgorithm::Md5,
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa",
            b"\x6f\x63\x0f\xad\x67\xcd\xa0\xee\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e",
        ),
        (
            DigestAlgorithm::Sha256,
            b"what do ya want for nothing?",
            b"Jefe",
            b"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\
           \x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43",
        ),
        (
            DigestAlgorithm::Sha256,
            b"Hi There",
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
           \x0b\x0b\x0b",
            b"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\
           \x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7",
        ),
        (
            DigestAlgorithm::Sha256,
            b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd",
            b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\
           \xAA\xAA\xAA\xAA",
            b"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\
           \x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe",
        ),
        (
            DigestAlgorithm::Sha256,
            b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd",
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
           \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
            b"\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\
           \x3a\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b",
        ),
        (
            DigestAlgorithm::Sha256,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa",
            b"\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f\
           \x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54",
        ),
        (
            DigestAlgorithm::Sha256,
            b"This is a test using a larger than block-size key and a larger than \
           block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa",
            b"\x9b\x09\xff\xa7\x1b\x94\x2f\xcb\x27\x63\x5f\xbc\xd5\xb0\xe9\x44\
           \xbf\xdc\x63\x64\x4f\x07\x13\x93\x8a\x7f\x51\x53\x5c\x3a\x35\xe2",
        ),
        (
            DigestAlgorithm::Sha224,
            b"what do ya want for nothing?",
            b"Jefe",
            b"\xa3\x0e\x01\x09\x8b\xc6\xdb\xbf\x45\x69\x0f\x3a\x7e\x9e\x6d\x0f\
           \x8b\xbe\xa2\xa3\x9e\x61\x48\x00\x8f\xd0\x5e\x44",
        ),
        (
            DigestAlgorithm::Sha224,
            b"Hi There",
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
           \x0b\x0b\x0b",
            b"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\
           \xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22",
        ),
        (
            DigestAlgorithm::Sha224,
            b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd",
            b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\
           \xAA\xAA\xAA\xAA",
            b"\x7f\xb3\xcb\x35\x88\xc6\xc1\xf6\xff\xa9\x69\x4d\x7d\x6a\xd2\x64\
           \x93\x65\xb0\xc1\xf6\x5d\x69\xd1\xec\x83\x33\xea",
        ),
        (
            DigestAlgorithm::Sha224,
            b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd",
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
           \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
            b"\x6c\x11\x50\x68\x74\x01\x3c\xac\x6a\x2a\xbc\x1b\xb3\x82\x62\
           \x7c\xec\x6a\x90\xd8\x6e\xfc\x01\x2d\xe7\xaf\xec\x5a",
        ),
        (
            DigestAlgorithm::Sha224,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa",
            b"\x95\xe9\xa0\xdb\x96\x20\x95\xad\xae\xbe\x9b\x2d\x6f\x0d\xbc\xe2\
           \xd4\x99\xf1\x12\xf2\xd2\xb7\x27\x3f\xa6\x87\x0e",
        ),
        (
            DigestAlgorithm::Sha224,
            b"This is a test using a larger than block-size key and a larger than \
           block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa",
            b"\x3a\x85\x41\x66\xac\x5d\x9f\x02\x3f\x54\xd5\x17\xd0\xb3\x9d\xbd\
           \x94\x67\x70\xdb\x9c\x2b\x95\xc9\xf6\xf5\x65\xd1",
        ),
        (
            DigestAlgorithm::Sha384,
            b"what do ya want for nothing?",
            b"Jefe",
            b"\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b\
           \x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e\
           \x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49",
        ),
        (
            DigestAlgorithm::Sha384,
            b"Hi There",
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
           \x0b\x0b\x0b",
            b"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\
           \xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\
           \x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6",
        ),
        (
            DigestAlgorithm::Sha384,
            b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd",
            b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\
           \xAA\xAA\xAA\xAA",
            b"\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f\
           \x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66\x14\x4b\
           \x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27",
        ),
        (
            DigestAlgorithm::Sha384,
            b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd",
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
           \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
            b"\x3e\x8a\x69\xb7\x78\x3c\x25\x85\x19\x33\xab\x62\x90\xaf\x6c\xa7\
           \x7a\x99\x81\x48\x08\x50\x00\x9c\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e\
           \x68\x01\xdd\x23\xc4\xa7\xd6\x79\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb",
        ),
        (
            DigestAlgorithm::Sha384,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa",
            b"\x4e\xce\x08\x44\x85\x81\x3e\x90\x88\xd2\xc6\x3a\x04\x1b\xc5\xb4\
           \x4f\x9e\xf1\x01\x2a\x2b\x58\x8f\x3c\xd1\x1f\x05\x03\x3a\xc4\xc6\
           \x0c\x2e\xf6\xab\x40\x30\xfe\x82\x96\x24\x8d\xf1\x63\xf4\x49\x52",
        ),
        (
            DigestAlgorithm::Sha384,
            b"This is a test using a larger than block-size key and a larger than \
           block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa",
            b"\x66\x17\x17\x8e\x94\x1f\x02\x0d\x35\x1e\x2f\x25\x4e\x8f\xd3\x2c\
           \x60\x24\x20\xfe\xb0\xb8\xfb\x9a\xdc\xce\xbb\x82\x46\x1e\x99\xc5\
           \xa6\x78\xcc\x31\xe7\x99\x17\x6d\x38\x60\xe6\x11\x0c\x46\x52\x3e",
        ),
        (
            DigestAlgorithm::Sha512,
            b"what do ya want for nothing?",
            b"Jefe",
            b"\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3\
           \x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54\
           \x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd\
           \xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37",
        ),
        (
            DigestAlgorithm::Sha512,
            b"Hi There",
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
           \x0b\x0b\x0b",
            b"\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\
           \x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\
           \xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\
           \xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54",
        ),
        (
            DigestAlgorithm::Sha512,
            b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd",
            b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\
           \xAA\xAA\xAA\xAA",
            b"\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9\
           \xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39\
           \xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07\
           \xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb",
        ),
        (
            DigestAlgorithm::Sha512,
            b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd",
            b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
           \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
            b"\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7\
           \xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb\
           \xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63\
           \xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd",
        ),
        (
            DigestAlgorithm::Sha512,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa",
            b"\x80\xb2\x42\x63\xc7\xc1\xa3\xeb\xb7\x14\x93\xc1\xdd\x7b\xe8\xb4\
           \x9b\x46\xd1\xf4\x1b\x4a\xee\xc1\x12\x1b\x01\x37\x83\xf8\xf3\x52\
           \x6b\x56\xd0\x37\xe0\x5f\x25\x98\xbd\x0f\xd2\x21\x5d\x6a\x1e\x52\
           \x95\xe6\x4f\x73\xf6\x3f\x0a\xec\x8b\x91\x5a\x98\x5d\x78\x65\x98",
        ),
        (
            DigestAlgorithm::Sha512,
            b"This is a test using a larger than block-size key and a larger than \
           block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa",
            b"\xe3\x7b\x6a\x77\x5d\xc8\x7d\xba\xa4\xdf\xa9\xf9\x6e\x5e\x3f\xfd\
           \xde\xbd\x71\xf8\x86\x72\x89\x86\x5d\xf5\xa3\x2d\x20\xcd\xc9\x44\
           \xb6\x02\x2c\xac\x3c\x49\x82\xb1\x0d\x5e\xeb\x55\xc3\xe4\xde\x15\
           \x13\x46\x76\xfb\x6d\xe0\x44\x60\x65\xc9\x74\x40\xfa\x8c\x6a\x58",
        ),
    ];

    for spec in specs {
        if !spec.0.is_available() {
            continue;
        }

        check_hmac(spec.0, spec.1, spec.2, spec.3);
    }
}

fn check_s2k() {
    let test_vectors: &[(&[u8], digest::Algorithm, Option<&[u8]>, u32, &[u8])] = &[
        (
            b"\x61",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61",
        ),
        (
            b"\x61\x62",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\x18\x7e\xf4\x43\x61\x22\xd1\xcc\x2f\x40\xdc\x2b\x92\xf0\xeb\xa0",
        ),
        (
            b"\x61\x62\x63",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72",
        ),
        (
            b"\x61\x62\x63\x64",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\xe2\xfc\x71\x4c\x47\x27\xee\x93\x95\xf3\x24\xcd\x2e\x7f\x33\x1f",
        ),
        (
            b"\x61\x62\x63\x64\x65",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\xab\x56\xb4\xd9\x2b\x40\x71\x3a\xcc\x5a\xf8\x99\x85\xd4\xb7\x86",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\xe8\x0b\x50\x17\x09\x89\x50\xfc\x58\xaa\xd8\x3c\x8c\x14\x97\x8e",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\x7a\xc6\x6c\x0f\x14\x8d\xe9\x51\x9b\x8b\xd2\x64\x31\x2c\x4d\x64",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\xe8\xdc\x40\x81\xb1\x34\x34\xb4\x51\x89\xa7\x20\xb7\x7b\x68\x18",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\x8a\xa9\x9b\x1f\x43\x9f\xf7\x12\x93\xe9\x53\x57\xba\xc6\xfd\x94",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\x8a\x73\x19\xdb\xf6\x54\x4a\x74\x22\xc9\xe2\x54\x52\x58\x0e\xa5",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\x1d\x64\xdc\xe2\x39\xc4\x43\x7b\x77\x36\x04\x1d\xb0\x89\xe1\xb9",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\x9a\x8d\x98\x45\xa6\xb4\xd8\x2d\xfc\xb2\xc2\xe3\x51\x62\xc8\x30",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\x35\x2a\xf0\xfc\xdf\xe9\xbb\x62\x16\xfc\x99\x9d\x8d\x58\x05\xcb",
        ),
        (
            b"\x57\x69\x74\x68\x5f\x75\x74\x66\x38\x5f\x75\x6d\x6c\x61\x75\x74\
           \x73\x3a\xc3\xa4\xc3\xbc\xc3\x96\xc3\x9f",
            DigestAlgorithm::Md5,
            None,
            0,
            b"\x21\xa4\xeb\xd8\xfd\xf0\x59\x25\xd1\x32\x31\xdb\xe7\xf2\x13\x5d",
        ),
        (
            b"\x61",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x86\xf7\xe4\x37\xfa\xa5\xa7\xfc\xe1\x5d\x1d\xdc\xb9\xea\xea\xea",
        ),
        (
            b"\x61\x62",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\xda\x23\x61\x4e\x02\x46\x9a\x0d\x7c\x7b\xd1\xbd\xab\x5c\x9c\x47",
        ),
        (
            b"\x61\x62\x63",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c",
        ),
        (
            b"\x61\x62\x63\x64",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x81\xfe\x8b\xfe\x87\x57\x6c\x3e\xcb\x22\x42\x6f\x8e\x57\x84\x73",
        ),
        (
            b"\x61\x62\x63\x64\x65",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x03\xde\x6c\x57\x0b\xfe\x24\xbf\xc3\x28\xcc\xd7\xca\x46\xb7\x6e",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x1f\x8a\xc1\x0f\x23\xc5\xb5\xbc\x11\x67\xbd\xa8\x4b\x83\x3e\x5c",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x2f\xb5\xe1\x34\x19\xfc\x89\x24\x68\x65\xe7\xa3\x24\xf4\x76\xec",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x42\x5a\xf1\x2a\x07\x43\x50\x2b\x32\x2e\x93\xa0\x15\xbc\xf8\x68",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\xc6\x3b\x19\xf1\xe4\xc8\xb5\xf7\x6b\x25\xc4\x9b\x8b\x87\xf5\x7d",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x29\x38\xdc\xc2\xe3\xaa\x77\x98\x7c\x7e\x5d\x4a\x0f\x26\x96\x67",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x14\xf3\x99\x52\x88\xac\xd1\x89\xe6\xe5\x0a\x7a\xf4\x7e\xe7\x09",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\xd8\x3d\x62\x1f\xcd\x2d\x4d\x29\x85\x54\x70\x43\xa7\xa5\xfd\x4d",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71\x72",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\xe3\x81\xfe\x42\xc5\x7e\x48\xa0\x82\x17\x86\x41\xef\xfd\x1c\xb9",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71\x72\x73",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x89\x3e\x69\xff\x01\x09\xf3\x45\x9c\x42\x43\x01\x3b\x3d\xe8\xb1",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71\x72\x73\x74",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x14\xa2\x3a\xd7\x0f\x2a\x5d\xd7\x25\x57\x5d\xe6\xc4\x3e\x1c\xdd",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71\x72\x73\x74\x75",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\xec\xa9\x86\xb9\x5d\x58\x7f\x34\xd7\x1c\xa7\x75\x2a\x4e\x00\x10",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x3e\x1b\x9a\x50\x7d\x6e\x9a\xd8\x93\x64\x96\x7a\x3f\xcb\x27\x3f",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\x3e\x1b\x9a\x50\x7d\x6e\x9a\xd8\x93\x64\x96\x7a\x3f\xcb\x27\x3f\
           \xc3\x7b\x3a\xb2\xef\x4d\x68\xaa\x9c\xd7\xe4\x88\xee\xd1\x5e\x70",
        ),
        (
            b"\x57\x69\x74\x68\x5f\x75\x74\x66\x38\x5f\x75\x6d\x6c\x61\x75\x74\
           \x73\x3a\xc3\xa4\xc3\xbc\xc3\x96\xc3\x9f",
            DigestAlgorithm::Sha1,
            None,
            0,
            b"\xe0\x4e\x1e\xe3\xad\x0b\x49\x7c\x7a\x5f\x37\x3b\x4d\x90\x3c\x2e",
        ),
        (
            b"\x61",
            DigestAlgorithm::Sha1,
            Some(b"\x6d\x47\xe3\x68\x5d\x2c\x36\x16"),
            1024,
            b"\x41\x9f\x48\x6e\xbf\xe6\xdd\x05\x9a\x72\x23\x17\x44\xd8\xd3\xf3",
        ),
        (
            b"\x61\x62",
            DigestAlgorithm::Sha1,
            Some(b"\x7c\x34\x78\xfb\x28\x2d\x25\xc7"),
            1024,
            b"\x0a\x9d\x09\x06\x43\x3d\x4f\xf9\x87\xd6\xf7\x48\x90\xde\xd1\x1c",
        ),
        (
            b"\x61\x62\x63",
            DigestAlgorithm::Sha1,
            Some(b"\xc3\x16\x37\x2e\x27\xf6\x9f\x6f"),
            1024,
            b"\xf8\x27\xa0\x07\xc6\xcb\xdd\xf1\xfe\x5c\x88\x3a\xfc\xcd\x84\x4d",
        ),
        (
            b"\x61\x62\x63\x64",
            DigestAlgorithm::Sha1,
            Some(b"\xf0\x0c\x73\x38\xb7\xc3\xd5\x14"),
            1024,
            b"\x9b\x5f\x26\xba\x52\x3b\xcd\xd9\xa5\x2a\xef\x3c\x03\x4d\xd1\x52",
        ),
        (
            b"\x61\x62\x63\x64\x65",
            DigestAlgorithm::Sha1,
            Some(b"\xe1\x7d\xa2\x36\x09\x59\xee\xc5"),
            1024,
            b"\x94\x9d\x5b\x1a\x5a\x66\x8c\xfa\x8f\x6f\x22\xaf\x8b\x60\x9f\xaf",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66",
            DigestAlgorithm::Sha1,
            Some(b"\xaf\xa7\x0c\x68\xdf\x7e\xaa\x27"),
            1024,
            b"\xe5\x38\xf4\x39\x62\x27\xcd\xcc\x91\x37\x7f\x1b\xdc\x58\x64\x27",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67",
            DigestAlgorithm::Sha1,
            Some(b"\x40\x57\xb2\x9d\x5f\xbb\x11\x4f"),
            1024,
            b"\xad\xa2\x33\xd9\xdd\xe0\xfb\x94\x8e\xcc\xec\xcc\xb3\xa8\x3a\x9e",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68",
            DigestAlgorithm::Sha1,
            Some(b"\x38\xf5\x65\xc5\x0f\x8c\x19\x61"),
            1024,
            b"\xa0\xb0\x3e\x29\x76\xe6\x8f\xa0\xd8\x34\x8f\xa4\x2d\xfd\x65\xee",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69",
            DigestAlgorithm::Sha1,
            Some(b"\xc3\xb7\x99\xcc\xda\x2d\x05\x7b"),
            1024,
            b"\x27\x21\xc8\x99\x5f\xcf\x20\xeb\xf2\xd9\xff\x6a\x69\xff\xad\xe8",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
            DigestAlgorithm::Sha1,
            Some(b"\x7d\xd8\x68\x8a\x1c\xc5\x47\x22"),
            1024,
            b"\x0f\x96\x7a\x12\x23\x54\xf6\x92\x61\x67\x07\xb4\x68\x17\xb8\xaa",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70",
            DigestAlgorithm::Sha1,
            Some(b"\x8a\x95\xd4\x88\x0b\xb8\xe9\x9d"),
            1024,
            b"\xcc\xe4\xc8\x82\x53\x32\xf1\x93\x5a\x00\xd4\x7f\xd4\x46\xfa\x07",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71",
            DigestAlgorithm::Sha1,
            Some(b"\xb5\x22\x48\xa6\xc4\xad\x74\x67"),
            1024,
            b"\x0c\xe3\xe0\xee\x3d\x8f\x35\xd2\x35\x14\x14\x29\x0c\xf1\xe3\x34",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71\x72",
            DigestAlgorithm::Sha1,
            Some(b"\xac\x9f\x04\x63\x83\x0e\x3c\x95"),
            1024,
            b"\x49\x0a\x04\x68\xa8\x2a\x43\x6f\xb9\x73\x94\xb4\x85\x9a\xaa\x0e",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71\x72\x73",
            DigestAlgorithm::Sha1,
            Some(b"\x03\x6f\x60\x30\x3a\x19\x61\x0d"),
            1024,
            b"\x15\xe5\x9b\xbf\x1c\xf0\xbe\x74\x95\x1a\xb2\xc4\xda\x09\xcd\x99",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71\x72\x73\x74",
            DigestAlgorithm::Sha1,
            Some(b"\x51\x40\xa5\x57\xf5\x28\xfd\x03"),
            1024,
            b"\xa6\xf2\x7e\x6b\x30\x4d\x8d\x67\xd4\xa2\x7f\xa2\x57\x27\xab\x96",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\
           \x71\x72\x73\x74\x75",
            DigestAlgorithm::Sha1,
            Some(b"\x4c\xf1\x10\x11\x04\x70\xd3\x6e"),
            1024,
            b"\x2c\x50\x79\x8d\x83\x23\xac\xd6\x22\x29\x37\xaf\x15\x0d\xdd\x8f",
        ),
        (
            b"\x57\x69\x74\x68\x5f\x75\x74\x66\x38\x5f\x75\x6d\x6c\x61\x75\x74\
           \x73\x3a\xc3\xa4\xc3\xbc\xc3\x96\xc3\x9f",
            DigestAlgorithm::Sha1,
            Some(b"\xfe\x3a\x25\xcb\x78\xef\xe1\x21"),
            1024,
            b"\x2a\xb0\x53\x08\xf3\x2f\xd4\x6e\xeb\x01\x49\x5d\x87\xf6\x27\xf6",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha1,
            Some(b"\x04\x97\xd0\x02\x6a\x44\x2d\xde"),
            1024,
            b"\x57\xf5\x70\x41\xa0\x9b\x8c\x09\xca\x74\xa9\x22\xa5\x82\x2d\x17",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha1,
            Some(b"\xdd\xf3\x31\x7c\xce\xf4\x81\x26"),
            10240,
            b"\xc3\xdd\x01\x6d\xaf\xf6\x58\xc8\xd7\x79\xb4\x40\x00\xb5\xe8\x0b",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha1,
            Some(b"\x95\xd6\x72\x4e\xfb\xe1\xc3\x1a"),
            102400,
            b"\xf2\x3f\x36\x7f\xb4\x6a\xd0\x3a\x31\x9e\x65\x11\x8e\x2b\x99\x9b",
        ),
        (
            b"\x61",
            DigestAlgorithm::Sha1,
            Some(b"\x6d\x69\x15\x18\xe4\x13\x42\x82"),
            1024,
            b"\x28\x0c\x7e\xf2\x31\xf6\x1c\x6b\x5c\xef\x6a\xd5\x22\x64\x97\x91\
           \xe3\x5e\x37\xfd\x50\xe2\xfc\x6c",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67",
            DigestAlgorithm::Sha1,
            Some(b"\x9b\x76\x5e\x81\xde\x13\xdf\x15"),
            1024,
            b"\x91\x1b\xa1\xc1\x7b\x4f\xc3\xb1\x80\x61\x26\x08\xbe\x53\xe6\x50\
           \x40\x6f\x28\xed\xc6\xe6\x67\x55",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69",
            DigestAlgorithm::Sha1,
            Some(b"\x7a\xac\xcc\x6e\x15\x56\xbd\xa1"),
            1024,
            b"\xfa\x7e\x20\x07\xb6\x47\xb0\x09\x46\xb8\x38\xfb\xa1\xaf\xf7\x75\
           \x2a\xfa\x77\x14\x06\x54\xcb\x34",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69",
            DigestAlgorithm::Sha1,
            Some(b"\x1c\x68\xf8\xfb\x98\xf7\x8c\x39"),
            1024,
            b"\xcb\x1e\x86\xf5\xe0\xe4\xfb\xbf\x71\x34\x99\x24\xf4\x39\x8c\xc2\
           \x8e\x25\x1c\x4c\x96\x47\x22\xe8",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha1,
            Some(b"\x10\xa9\x4e\xc1\xa5\xec\x17\x52"),
            1024,
            b"\x0f\x83\xa2\x77\x92\xbb\xe4\x58\x68\xc5\xf2\x14\x6e\x6e\x2e\x6b\
           \x98\x17\x70\x92\x07\x44\xe0\x51",
        ),
        (
            b"\x61",
            DigestAlgorithm::Sha1,
            Some(b"\xef\x8f\x37\x61\x8f\xab\xae\x4f"),
            1024,
            b"\x6d\x65\xae\x86\x23\x91\x39\x98\xec\x1c\x23\x44\xb6\x0d\xad\x32\
           \x54\x46\xc7\x23\x26\xbb\xdf\x4b\x54\x6e\xd4\xc2\xfa\xc6\x17\x17",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67",
            DigestAlgorithm::Sha1,
            Some(b"\xaa\xfb\xd9\x06\x7d\x7c\x40\xaf"),
            1024,
            b"\x7d\x10\x54\x13\x3c\x43\x7a\xb3\x54\x1f\x38\xd4\x8f\x70\x0a\x09\
           \xe2\xfa\xab\x97\x9a\x70\x16\xef\x66\x68\xca\x34\x2e\xce\xfa\x1f",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69",
            DigestAlgorithm::Sha1,
            Some(b"\x58\x03\x4f\x56\x8b\x97\xd4\x98"),
            1024,
            b"\xf7\x40\xb1\x25\x86\x0d\x35\x8f\x9f\x91\x2d\xce\x04\xee\x5a\x04\
           \x9d\xbd\x44\x23\x4c\xa6\xbb\xab\xb0\xd0\x56\x82\xa9\xda\x47\x16",
        ),
        (
            b"\x61\x62\x63\x64\x65\x66\x67\x68\x69",
            DigestAlgorithm::Sha1,
            Some(b"\x5d\x41\x3d\xa3\xa7\xfc\x5d\x0c"),
            1024,
            b"\x4c\x7a\x86\xed\x81\x8a\x94\x99\x7d\x4a\xc4\xf7\x1c\xf8\x08\xdb\
           \x09\x35\xd9\xa3\x2d\x22\xde\x32\x2d\x74\x38\xe5\xc8\xf2\x50\x6e",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha1,
            Some(b"\xca\xa7\xdc\x59\xce\x31\xe7\x49"),
            1024,
            b"\x67\xe9\xd6\x29\x49\x1c\xb6\xa0\x85\xe8\xf9\x8b\x85\x47\x3a\x7e\
           \xa7\xee\x89\x52\x6f\x19\x00\x53\x93\x07\x0a\x8b\xb9\xa8\x86\x94",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha256,
            None,
            0,
            b"\x88\x36\x78\x6b\xd9\x5a\x62\xff\x47\xd3\xfb\x79\xc9\x08\x70\x56",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha256,
            Some(b"\x05\x8b\xfe\x31\xaa\xf3\x29\x11"),
            0,
            b"\xb2\x42\xfe\x5e\x09\x02\xd9\x62\xb9\x35\xf3\xa8\x43\x80\x9f\xb1",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha256,
            Some(b"\xd3\x4a\xea\xc9\x97\x1b\xcc\x83"),
            1024,
            b"\x35\x37\x99\x62\x07\x26\x68\x23\x05\x47\xb2\xa0\x0b\x2b\x2b\x8d",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha256,
            Some(b"\x5e\x71\xbd\x00\x5f\x96\xc4\x23"),
            10240,
            b"\xa1\x6a\xee\xba\xde\x73\x25\x25\xd1\xab\xa0\xc5\x7e\xc6\x39\xa7",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha384,
            Some(b"\xc3\x08\xeb\x17\x62\x08\x89\xef"),
            1024,
            b"\x9b\x7f\x0c\x81\x6f\x71\x59\x9b\xd5\xf6\xbf\x3a\x86\x20\x16\x33",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha512,
            Some(b"\xe6\x7d\x13\x6b\x39\xe3\x44\x05"),
            1024,
            b"\xc8\xcd\x4b\xa4\xf3\xf1\xd5\xb0\x59\x06\xf0\xbb\x89\x34\x6a\xad",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha512,
            Some(b"\xed\x7d\x30\x47\xe4\xc3\xf8\xb6"),
            1024,
            b"\x89\x7a\xef\x70\x97\xe7\x10\xdb\x75\xcc\x20\x22\xab\x7b\xf3\x05\
           \x4b\xb6\x2e\x17\x11\x9f\xd6\xeb\xbf\xdf\x4d\x70\x59\xf0\xf9\xe5",
        ),
        (
            b"\x4c\x6f\x6e\x67\x5f\x73\x65\x6e\x74\x65\x6e\x63\x65\x5f\x75\x73\
           \x65\x64\x5f\x61\x73\x5f\x70\x61\x73\x73\x70\x68\x72\x61\x73\x65",
            DigestAlgorithm::Sha512,
            Some(b"\xbb\x1a\x45\x30\x68\x62\x6d\x63"),
            1024,
            b"\xde\x5c\xb8\xd5\x75\xf6\xad\x69\x5b\xc9\xf6\x2f\xba\xeb\xfb\x36\
           \x34\xf2\xb8\xee\x3b\x37\x21\xb7",
        ),
    ];

    let mut key = [0u8; 32];
    for tv in test_vectors {
        assert!(tv.4.len() <= key.len());
        kdf::s2k_derive(tv.1, tv.3, tv.0, tv.2, &mut key[..tv.4.len()]).unwrap();
        assert_eq!(tv.4, &key[..tv.4.len()]);
    }
}

fn check_pbkdf2() {
    let test_vectors: &[(&str, &str, u32, &[u8])] = &[
        (
            "password",
            "salt",
            1,
            b"\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\
           \xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6",
        ),
        (
            "password",
            "salt",
            2,
            b"\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\
           \xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57",
        ),
        (
            "password",
            "salt",
            4096,
            b"\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\
           \x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1",
        ),
        (
            "passwordPASSWORDpassword",
            "saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            b"\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\
           \xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96\
           \x4c\xf2\xf0\x70\x38",
        ),
        (
            "pass\0word",
            "sa\0lt",
            4096,
            b"\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\
           \xd7\xf0\x34\x25\xe0\xc3",
        ),
    ];

    let mut key = [0u8; 32];
    for tv in test_vectors {
        assert!(tv.3.len() <= key.len());
        kdf::pbkdf2_derive(
            DigestAlgorithm::Sha1,
            tv.2,
            tv.0.as_bytes(),
            tv.1.as_bytes(),
            &mut key[..tv.3.len()],
        ).unwrap();
        assert_eq!(tv.3, &key[..tv.3.len()]);
    }
}

fn check_scrypt() {
    let test_vectors: &[(&str, &str, u32, u32, &[u8])] = &[
        (
            "password",
            "NaCl",
            1024,
            16,
            b"\xfd\xba\xbe\x1c\x9d\x34\x72\x00\x78\x56\xe7\x19\x0d\x01\xe9\xfe\
           \x7c\x6a\xd7\xcb\xc8\x23\x78\x30\xe7\x73\x76\x63\x4b\x37\x31\x62\
           \x2e\xaf\x30\xd9\x2e\x22\xa3\x88\x6f\xf1\x09\x27\x9d\x98\x30\xda\
           \xc7\x27\xaf\xb9\x4a\x83\xee\x6d\x83\x60\xcb\xdf\xa2\xcc\x06\x40",
        ),
        (
            "pleaseletmein",
            "SodiumChloride",
            16384,
            1,
            b"\x70\x23\xbd\xcb\x3a\xfd\x73\x48\x46\x1c\x06\xcd\x81\xfd\x38\xeb\
           \xfd\xa8\xfb\xba\x90\x4f\x8e\x3e\xa9\xb5\x43\xf6\x54\x5d\xa1\xf2\
           \xd5\x43\x29\x55\x61\x3f\x0f\xcf\x62\xd4\x97\x05\x24\x2a\x9a\xf9\
           \xe6\x1e\x85\xdc\x0d\x65\x1e\x40\xdf\xcf\x01\x7b\x45\x57\x58\x87",
        ),
    ];

    let mut key = [0u8; 64];
    for tv in test_vectors {
        assert!(tv.4.len() <= key.len());
        kdf::scrypt_derive(
            tv.2,
            tv.3,
            tv.0.as_bytes(),
            tv.1.as_bytes(),
            &mut key[..tv.4.len()],
        ).unwrap();
        assert_eq!(tv.4, &key[..tv.4.len()]);
    }
}

#[test]
fn test_kdfs() {
    let token = setup();

    check_s2k();
    check_pbkdf2();
    if token.check_version("1.6.0") {
        check_scrypt();
    }
}

const FLAG_CRYPT: usize = 1;
const FLAG_SIGN: usize = 2;
const FLAG_GRIP: usize = 4;

fn verify_signature(
    pkey: &SExpression, hash: &SExpression, bad_hash: &SExpression, sig: &SExpression,
) {
    assert_eq!(pkey::verify(pkey, hash, sig), Ok(()));
    assert_eq!(
        pkey::verify(pkey, bad_hash, sig).map_err(|e| e.with_source(Error::SOURCE_UNKNOWN)),
        Err(Error::BAD_SIGNATURE)
    );
}

fn check_pkey_sign(algo: KeyAlgorithm, skey: &SExpression, pkey: &SExpression) {
    let specs: &[(&[u8], Option<KeyAlgorithm>, Error)] = &[
        (
            b"(data\n (flags pkcs1)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
            Some(KeyAlgorithm::Rsa),
            Error::NO_ERROR,
        ),
        (
            b"(data\n (flags oaep)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
            None,
            Error::CONFLICT,
        ),
        (
            b"(data\n (flags pkcs1)\n\
            (hash oid.1.3.14.3.2.29 \
                  #11223344556677889900AABBCCDDEEFF10203040#))\n",
            Some(KeyAlgorithm::Rsa),
            Error::NO_ERROR,
        ),
        (
            b"(data\n (flags )\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
            None,
            Error::CONFLICT,
        ),
        (
            b"(data\n (flags pkcs1)\n\
            (hash foo #11223344556677889900AABBCCDDEEFF10203040#))\n",
            Some(KeyAlgorithm::Rsa),
            Error::DIGEST_ALGO,
        ),
        (
            b"(data\n (flags )\n (value #11223344556677889900AA#))\n",
            None,
            Error::NO_ERROR,
        ),
        (
            b"(data\n (flags )\n (value #0090223344556677889900AA#))\n",
            None,
            Error::NO_ERROR,
        ),
        (
            b"(data\n (flags raw)\n (value #11223344556677889900AA#))\n",
            None,
            Error::NO_ERROR,
        ),
        (
            b"(data\n (flags pkcs1)\n (value #11223344556677889900AA#))\n",
            Some(KeyAlgorithm::Rsa),
            Error::CONFLICT,
        ),
        (
            b"(data\n (flags raw foo)\n (value #11223344556677889900AA#))\n",
            None,
            Error::INV_FLAG,
        ),
        (
            b"(data\n (flags pss)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
            Some(KeyAlgorithm::Rsa),
            Error::NO_ERROR,
        ),
        (
            b"(data\n (flags pss)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#)\n\
            (random-override #4253647587980912233445566778899019283747#))\n",
            Some(KeyAlgorithm::Rsa),
            Error::NO_ERROR,
        ),
    ];

    let bad_hash = SExpression::from_bytes(
        &b"(data\n (flags pkcs1)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203041#))\n"[..],
    ).unwrap();

    for spec in specs {
        if spec.1.is_some() && (spec.1 != Some(algo)) {
            continue;
        }

        let hash = SExpression::from_bytes(spec.0).unwrap();
        let sig = match pkey::sign(&skey, &hash) {
            Ok(s) => s,
            Err(e) => {
                assert_eq!(spec.2, e.with_source(Error::SOURCE_UNKNOWN));
                return;
            }
        };
        verify_signature(pkey, &hash, &bad_hash, &sig);
    }
}

fn check_pkey_sign_ecdsa(skey: &SExpression, pkey: &SExpression) {
    let specs: &[(usize, &[u8], Error, &[u8])] = &[
        (
            192,
            b"(data (flags raw)\n\
            (value #00112233445566778899AABBCCDDEEFF0001020304050607#))",
            Error::NO_ERROR,
            b"(data (flags raw)\n\
           (value #80112233445566778899AABBCCDDEEFF0001020304050607#))",
        ),
        (
            256,
            b"(data (flags raw)\n\
            (value #00112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F#))",
            Error::NO_ERROR,
            b"(data (flags raw)\n\
            (value #80112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F#))",
        ),
        (
            256,
            b"(data (flags raw)\n\
            (hash sha256 #00112233445566778899AABBCCDDEEFF\
                          000102030405060708090A0B0C0D0E0F#))",
            Error::NO_ERROR,
            b"(data (flags raw)\n\
            (hash sha256 #80112233445566778899AABBCCDDEEFF\
                          000102030405060708090A0B0C0D0E0F#))",
        ),
        (
            256,
            b"(data (flags gost)\n\
            (value #00112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F#))",
            Error::NO_ERROR,
            b"(data (flags gost)\n\
            (value #80112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F#))",
        ),
        (
            512,
            b"(data (flags gost)\n\
            (value #00112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F\
                    000102030405060708090A0B0C0D0E0F\
                    000102030405060708090A0B0C0D0E0F#))",
            Error::NO_ERROR,
            b"(data (flags gost)\n\
            (value #80112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F\
                    000102030405060708090A0B0C0D0E0F\
                    000102030405060708090A0B0C0D0E0F#))",
        ),
    ];

    let nbits = pkey::num_bits(&skey);
    for spec in specs {
        if Some(spec.0) != nbits {
            continue;
        }

        let hash = SExpression::from_bytes(spec.1).unwrap();
        let bad_hash = SExpression::from_bytes(spec.3).unwrap();
        let sig = match pkey::sign(&skey, &hash) {
            Ok(s) => s,
            Err(e) => {
                assert_eq!(spec.2, e);
                return;
            }
        };
        verify_signature(pkey, &hash, &bad_hash, &sig);
    }
}

fn check_pkey_crypt(algo: pkey::Algorithm, skey: &SExpression, pkey: &SExpression) {
    let specs: &[(
        Option<pkey::Algorithm>,
        &[u8],
        &[u8],
        bool,
        Error,
        Error,
        bool,
    )] = &[
        (
            Some(KeyAlgorithm::Rsa),
            b"(data\n (flags pkcs1)\n\
            (value #11223344556677889900AA#))\n",
            b"",
            false,
            Error::NO_ERROR,
            Error::NO_ERROR,
            false,
        ),
        (
            Some(KeyAlgorithm::Rsa),
            b"(data\n (flags pkcs1)\n\
            (value #11223344556677889900AA#))\n",
            b"(flags pkcs1)",
            true,
            Error::NO_ERROR,
            Error::NO_ERROR,
            false,
        ),
        (
            Some(KeyAlgorithm::Rsa),
            b"(data\n (flags oaep)\n\
            (value #11223344556677889900AA#))\n",
            b"(flags oaep)",
            true,
            Error::NO_ERROR,
            Error::NO_ERROR,
            false,
        ),
        (
            Some(KeyAlgorithm::Rsa),
            b"(data\n (flags oaep)\n (hash-algo sha1)\n\
            (value #11223344556677889900AA#))\n",
            b"(flags oaep)(hash-algo sha1)",
            true,
            Error::NO_ERROR,
            Error::NO_ERROR,
            false,
        ),
        (
            Some(KeyAlgorithm::Rsa),
            b"(data\n (flags oaep)\n (hash-algo sha1)\n (label \"test\")\n\
            (value #11223344556677889900AA#))\n",
            b"(flags oaep)(hash-algo sha1)(label \"test\")",
            true,
            Error::NO_ERROR,
            Error::NO_ERROR,
            false,
        ),
        (
            Some(KeyAlgorithm::Rsa),
            b"(data\n (flags oaep)\n (hash-algo sha1)\n (label \"test\")\n\
            (value #11223344556677889900AA#)\n\
            (random-override #4253647587980912233445566778899019283747#))\n",
            b"(flags oaep)(hash-algo sha1)(label \"test\")",
            true,
            Error::NO_ERROR,
            Error::NO_ERROR,
            false,
        ),
        (
            None,
            b"(data\n (flags )\n (value #11223344556677889900AA#))\n",
            b"",
            true,
            Error::NO_ERROR,
            Error::NO_ERROR,
            false,
        ),
        (
            None,
            b"(data\n (flags )\n (value #0090223344556677889900AA#))\n",
            b"",
            true,
            Error::NO_ERROR,
            Error::NO_ERROR,
            false,
        ),
        (
            None,
            b"(data\n (flags raw)\n (value #11223344556677889900AA#))\n",
            b"",
            true,
            Error::NO_ERROR,
            Error::NO_ERROR,
            false,
        ),
        (
            Some(KeyAlgorithm::Rsa),
            b"(data\n (flags pkcs1)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
            b"",
            false,
            Error::CONFLICT,
            Error::NO_ERROR,
            false,
        ),
        (
            None,
            b"(data\n (flags raw foo)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
            b"",
            false,
            Error::INV_FLAG,
            Error::NO_ERROR,
            false,
        ),
        (
            None,
            b"(data\n (flags raw)\n (value #11223344556677889900AA#))\n",
            b"(flags oaep)",
            true,
            Error::NO_ERROR,
            Error::ENCODING_PROBLEM,
            true,
        ),
        (
            Some(KeyAlgorithm::Rsa),
            b"(data\n (flags oaep)\n (value #11223344556677889900AA#))\n",
            b"(flags pkcs1)",
            true,
            Error::NO_ERROR,
            Error::ENCODING_PROBLEM,
            true,
        ),
        (
            None,
            b"(data\n (flags pss)\n (value #11223344556677889900AA#))\n",
            b"",
            false,
            Error::CONFLICT,
            Error::NO_ERROR,
            false,
        ),
    ];

    for spec in specs {
        if spec.0.is_some() && (spec.0 != Some(algo)) {
            continue;
        }

        let data = SExpression::from_bytes(spec.1).unwrap();
        let cipher = {
            let cipher = match pkey::encrypt(&pkey, &data) {
                Ok(s) => s,
                Err(e) => {
                    assert_eq!(spec.4, e.with_source(Error::SOURCE_UNKNOWN));
                    return;
                }
            };

            if !spec.2.is_empty() {
                let hint = SExpression::from_bytes(spec.2)
                    .unwrap()
                    .to_bytes(sexp::Format::Canonical);
                let len = cipher.len_encoded(sexp::Format::Canonical) + hint.len();
                let mut buffer = vec![0u8; len];
                cipher.encode(sexp::Format::Canonical, &mut buffer[hint.len()..]);
                for i in (0..10).rev() {
                    buffer[i] = buffer[i + hint.len()];
                }
                (&mut buffer[10..(10 + hint.len())]).copy_from_slice(&hint);
                SExpression::from_bytes(buffer).unwrap()
            } else {
                cipher
            }
        };
        let plain = match pkey::decrypt(&skey, &cipher) {
            Ok(s) => s,
            Err(e) => {
                assert_eq!(spec.5, e.with_source(Error::SOURCE_UNKNOWN));
                return;
            }
        };
        if spec.3 {
            let p1 = data.find_token("value");
            let p2 = plain.find_token("value");
            if let (Some(p1), Some(p2)) = (p1, p2) {
                let s1 = p1.get_bytes(1);
                let s2 = p2.get_bytes(1);
                assert_eq!(!spec.6, s1 == s2);
            } else {
                assert!(!spec.6);
            }
        }
    }
}

fn check_pkey(
    algo: pkey::Algorithm, flags: usize, skey: &SExpression, pkey: &SExpression, grip: &[u8],
) {
    if (flags & FLAG_SIGN) == FLAG_SIGN {
        if algo == KeyAlgorithm::Ecdsa {
            check_pkey_sign_ecdsa(skey, pkey);
        } else {
            check_pkey_sign(algo, skey, pkey);
        }
    }
    if (flags & FLAG_CRYPT) == FLAG_CRYPT {
        check_pkey_crypt(algo, skey, pkey);
    }
    if (flags & FLAG_GRIP) == FLAG_GRIP {
        assert_eq!(grip, pkey::key_grip(&skey).unwrap());
        assert_eq!(grip, pkey::key_grip(&pkey).unwrap());
    }
}

#[test]
fn test_pkey() {
    setup();

    let keys: &[(pkey::Algorithm, usize, (&[u8], &[u8], &[u8]))] = &[
        (
            KeyAlgorithm::Rsa,
            FLAG_CRYPT | FLAG_SIGN,
            (
                b"(private-key\n\
           (rsa\n\
            (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa\
                2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291\
                ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7\
                891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea2\
                51#)\n\
            (e #010001#)\n\
            (d #046129F2489D71579BE0A75FE029BD6CDB574EBF57EA8A5B0FDA942CAB943B11\
                7D7BB95E5D28875E0F9FC5FCC06A72F6D502464DABDED78EF6B716177B83D5BD\
                C543DC5D3FED932E59F5897E92E6F58A0F33424106A3B6FA2CBF877510E4AC21\
                C3EE47851E97D12996222AC3566D4CCB0B83D164074ABF7DE655FC2446DA1781\
                #)\n\
            (p #00e861b700e17e8afe6837e7512e35b6ca11d0ae47d8b85161c67baf64377213\
                fe52d772f2035b3ca830af41d8a4120e1c1c70d12cc22f00d28d31dd48a8d424\
                f1#)\n\
            (q #00f7a7ca5367c661f8e62df34f0d05c10c88e5492348dd7bddc942c9a8f369f9\
                35a07785d2db805215ed786e4285df1658eed3ce84f469b81b50d358407b4ad3\
                61#)\n\
            (u #304559a9ead56d2309d203811a641bb1a09626bc8eb36fffa23c968ec5bd891e\
                ebbafc73ae666e01ba7c8990bae06cc2bbe10b75e69fcacb353a6473079d8e9b\
                #)))\n",
                b"(public-key\n\
           (rsa\n\
            (n #00e0ce96f90b6c9e02f3922beada93fe50a875eac6bcc18bb9a9cf2e84965caa\
                2d1ff95a7f542465c6c0c19d276e4526ce048868a7a914fd343cc3a87dd74291\
                ffc565506d5bbb25cbac6a0e2dd1f8bcaab0d4a29c2f37c950f363484bf269f7\
                891440464baf79827e03a36e70b814938eebdc63e964247be75dc58b014b7ea2\
                51#)\n\
            (e #010001#)))\n",
                b"\x32\x10\x0c\x27\x17\x3e\xf6\xe9\xc4\xe9\
          \xa2\x5d\x3d\x69\xf8\x6d\x37\xa4\xf9\x39",
            ),
        ),
        (
            KeyAlgorithm::Dsa,
            FLAG_SIGN,
            (
                b"(private-key\n\
           (DSA\n\
            (p #00AD7C0025BA1A15F775F3F2D673718391D00456978D347B33D7B49E7F32EDAB\
                96273899DD8B2BB46CD6ECA263FAF04A28903503D59062A8865D2AE8ADFB5191\
                CF36FFB562D0E2F5809801A1F675DAE59698A9E01EFE8D7DCFCA084F4C6F5A44\
                44D499A06FFAEA5E8EF5E01F2FD20A7B7EF3F6968AFBA1FB8D91F1559D52D877\
                7B#)\n\
            (q #00EB7B5751D25EBBB7BD59D920315FD840E19AEBF9#)\n\
            (g #1574363387FDFD1DDF38F4FBE135BB20C7EE4772FB94C337AF86EA8E49666503\
                AE04B6BE81A2F8DD095311E0217ACA698A11E6C5D33CCDAE71498ED35D13991E\
                B02F09AB40BD8F4C5ED8C75DA779D0AE104BC34C960B002377068AB4B5A1F984\
                3FBA91F537F1B7CAC4D8DD6D89B0D863AF7025D549F9C765D2FC07EE208F8D15\
                #)\n\
            (y #64B11EF8871BE4AB572AA810D5D3CA11A6CDBC637A8014602C72960DB135BF46\
                A1816A724C34F87330FC9E187C5D66897A04535CC2AC9164A7150ABFA8179827\
                6E45831AB811EEE848EBB24D9F5F2883B6E5DDC4C659DEF944DCFD80BF4D0A20\
                42CAA7DC289F0C5A9D155F02D3D551DB741A81695B74D4C8F477F9C7838EB0FB\
                #)\n\
            (x #11D54E4ADBD3034160F2CED4B7CD292A4EBF3EC0#)))\n",
                b"(public-key\n\
           (DSA\n\
            (p #00AD7C0025BA1A15F775F3F2D673718391D00456978D347B33D7B49E7F32EDAB\
                96273899DD8B2BB46CD6ECA263FAF04A28903503D59062A8865D2AE8ADFB5191\
                CF36FFB562D0E2F5809801A1F675DAE59698A9E01EFE8D7DCFCA084F4C6F5A44\
                44D499A06FFAEA5E8EF5E01F2FD20A7B7EF3F6968AFBA1FB8D91F1559D52D877\
                7B#)\n\
            (q #00EB7B5751D25EBBB7BD59D920315FD840E19AEBF9#)\n\
            (g #1574363387FDFD1DDF38F4FBE135BB20C7EE4772FB94C337AF86EA8E49666503\
                AE04B6BE81A2F8DD095311E0217ACA698A11E6C5D33CCDAE71498ED35D13991E\
                B02F09AB40BD8F4C5ED8C75DA779D0AE104BC34C960B002377068AB4B5A1F984\
                3FBA91F537F1B7CAC4D8DD6D89B0D863AF7025D549F9C765D2FC07EE208F8D15\
                #)\n\
            (y #64B11EF8871BE4AB572AA810D5D3CA11A6CDBC637A8014602C72960DB135BF46\
                A1816A724C34F87330FC9E187C5D66897A04535CC2AC9164A7150ABFA8179827\
                6E45831AB811EEE848EBB24D9F5F2883B6E5DDC4C659DEF944DCFD80BF4D0A20\
                42CAA7DC289F0C5A9D155F02D3D551DB741A81695B74D4C8F477F9C7838EB0FB\
                #)))\n",
                b"\xc6\x39\x83\x1a\x43\xe5\x05\x5d\xc6\xd8\
          \x4a\xa6\xf9\xeb\x23\xbf\xa9\x12\x2d\x5b",
            ),
        ),
        (
            KeyAlgorithm::Elg,
            FLAG_SIGN | FLAG_CRYPT,
            (
                b"(private-key\n\
           (ELG\n\
            (p #00B93B93386375F06C2D38560F3B9C6D6D7B7506B20C1773F73F8DE56E6CD65D\
                F48DFAAA1E93F57A2789B168362A0F787320499F0B2461D3A4268757A7B27517\
                B7D203654A0CD484DEC6AF60C85FEB84AAC382EAF2047061FE5DAB81A20A0797\
                6E87359889BAE3B3600ED718BE61D4FC993CC8098A703DD0DC942E965E8F18D2\
                A7#)\n\
            (g #05#)\n\
            (y #72DAB3E83C9F7DD9A931FDECDC6522C0D36A6F0A0FEC955C5AC3C09175BBFF2B\
                E588DB593DC2E420201BEB3AC17536918417C497AC0F8657855380C1FCF11C5B\
                D20DB4BEE9BDF916648DE6D6E419FA446C513AAB81C30CB7B34D6007637BE675\
                56CE6473E9F9EE9B9FADD275D001563336F2186F424DEC6199A0F758F6A00FF4\
                #)\n\
            (x #03C28900087B38DABF4A0AB98ACEA39BB674D6557096C01D72E31C16BDD32214\
                #)))\n",
                b"(public-key\n\
           (ELG\n\
            (p #00B93B93386375F06C2D38560F3B9C6D6D7B7506B20C1773F73F8DE56E6CD65D\
                F48DFAAA1E93F57A2789B168362A0F787320499F0B2461D3A4268757A7B27517\
                B7D203654A0CD484DEC6AF60C85FEB84AAC382EAF2047061FE5DAB81A20A0797\
                6E87359889BAE3B3600ED718BE61D4FC993CC8098A703DD0DC942E965E8F18D2\
                A7#)\n\
            (g #05#)\n\
            (y #72DAB3E83C9F7DD9A931FDECDC6522C0D36A6F0A0FEC955C5AC3C09175BBFF2B\
                E588DB593DC2E420201BEB3AC17536918417C497AC0F8657855380C1FCF11C5B\
                D20DB4BEE9BDF916648DE6D6E419FA446C513AAB81C30CB7B34D6007637BE675\
                56CE6473E9F9EE9B9FADD275D001563336F2186F424DEC6199A0F758F6A00FF4\
                #)))\n",
                b"\xa7\x99\x61\xeb\x88\x83\xd2\xf4\x05\xc8\
          \x4f\xba\x06\xf8\x78\x09\xbc\x1e\x20\xe5",
            ),
        ),
        (
            KeyAlgorithm::Ecdsa,
            FLAG_SIGN,
            (
                b"(private-key\n\
           (ecdsa\n\
            (curve nistp192)\n\
            (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE\
                  C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)\n\
            (d #00D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D#)))\n",
                b"(public-key\n\
           (ecdsa\n\
            (curve nistp192)\n\
            (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE\
                  C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)))\n",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        ),
        (
            KeyAlgorithm::Ecdsa,
            FLAG_SIGN,
            (
                b"(private-key\n\
           (ecdsa\n\
            (curve nistp192)\n\
            (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE\
                  C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)\n\
            (d #00D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D#)))\n",
                b"(public-key\n\
           (ecc\n\
            (curve nistp192)\n\
            (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE\
                  C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)))\n",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        ),
        (
            KeyAlgorithm::Ecdsa,
            FLAG_SIGN,
            (
                b"(private-key\n\
           (ecc\n\
            (curve nistp192)\n\
            (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE\
                  C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)\n\
            (d #00D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D#)))\n",
                b"(public-key\n\
           (ecdsa\n\
            (curve nistp192)\n\
            (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE\
                  C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)))\n",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        ),
        (
            KeyAlgorithm::Ecdsa,
            FLAG_SIGN,
            (
                b"(private-key\n\
           (ecc\n\
            (curve nistp192)\n\
            (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE\
                  C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)\n\
            (d #00D4EF27E32F8AD8E2A1C6DDEBB1D235A69E3CEF9BCE90273D#)))\n",
                b"(public-key\n\
           (ecc\n\
            (curve nistp192)\n\
            (q #048532093BA023F4D55C0424FA3AF9367E05F309DC34CDC3FE\
                  C13CA9E617C6C8487BFF6A726E3C4F277913D97117939966#)))\n",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        ),
        (
            KeyAlgorithm::Ecdsa,
            FLAG_SIGN,
            (
                b"(private-key\n\
           (ecc\n\
            (curve nistp256)\n\
            (q #04D4F6A6738D9B8D3A7075C1E4EE95015FC0C9B7E4272D2B\
                EB6644D3609FC781B71F9A8072F58CB66AE2F89BB1245187\
                3ABF7D91F9E1FBF96BF2F70E73AAC9A283#)\n\
            (d #5A1EF0035118F19F3110FB81813D3547BCE1E5BCE77D1F74\
                4715E1D5BBE70378#)))\n",
                b"(public-key\n\
           (ecc\n\
            (curve nistp256)\n\
            (q #04D4F6A6738D9B8D3A7075C1E4EE95015FC0C9B7E4272D2B\
                EB6644D3609FC781B71F9A8072F58CB66AE2F89BB1245187\
                3ABF7D91F9E1FBF96BF2F70E73AAC9A283#)))\n",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        ),
        (
            KeyAlgorithm::Ecdsa,
            FLAG_SIGN,
            (
                b"(private-key\n\
           (ecc\n\
            (curve GOST2001-test)\n\
            (q #047F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B78\
                8F6689DBD8E56FD80B26F1B489D6701DD185C8413A977B3C\
                BBAF64D1C593D26627DFFB101A87FF77DA#)\n\
            (d #7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE\
                1D19CE9891EC3B28#)))\n",
                b"(public-key\n\
           (ecc\n\
            (curve GOST2001-test)\n\
            (q #047F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B78\
                8F6689DBD8E56FD80B26F1B489D6701DD185C8413A977B3C\
                BBAF64D1C593D26627DFFB101A87FF77DA#)))\n",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        ),
        (
            KeyAlgorithm::Ecdsa,
            FLAG_SIGN,
            (
                b"(private-key\n\
           (ecc\n\
            (curve GOST2012-test)\n\
            (q #04115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1\
                  815B5C320C854621DD5A515856D13314AF69BC5B924C8B\
                  4DDFF75C45415C1D9DD9DD33612CD530EFE137C7C90CD4\
                  0B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7F\
                  B72AFD61EA199441D943FFE7F0C70A2759A3CDB84C114E\
                  1F9339FDF27F35ECA93677BEEC#)\n\
            (d #0BA6048AADAE241BA40936D47756D7C93091A0E851466970\
                0EE7508E508B102072E8123B2200A0563322DAD2827E2714\
                A2636B7BFD18AADFC62967821FA18DD4#)))\n",
                b"(public-key\n\
           (ecc\n\
            (curve GOST2001-test)\n\
            (q #04115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1\
                  815B5C320C854621DD5A515856D13314AF69BC5B924C8B\
                  4DDFF75C45415C1D9DD9DD33612CD530EFE137C7C90CD4\
                  0B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7F\
                  B72AFD61EA199441D943FFE7F0C70A2759A3CDB84C114E\
                  1F9339FDF27F35ECA93677BEEC#)))\n",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ),
        ),
    ];
    for &(algo, flags, key) in keys {
        if !algo.is_available() {
            continue;
        }
        let skey = SExpression::from_bytes(key.0).unwrap();
        let pkey = SExpression::from_bytes(key.1).unwrap();
        check_pkey(algo, flags, &skey, &pkey, key.2);
    }

    let key_spec = "(genkey (rsa (nbits 4:1024)))"
        .parse::<SExpression>()
        .unwrap();
    let key = pkey::generate_key(&key_spec).unwrap();
    let pkey = key.find_token("public-key").unwrap();
    let skey = key.find_token("private-key").unwrap();
    check_pkey(KeyAlgorithm::Rsa, FLAG_SIGN | FLAG_CRYPT, &skey, &pkey, b"");
}
