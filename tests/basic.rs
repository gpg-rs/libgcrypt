extern crate gcrypt;

use gcrypt::Token;
use gcrypt::error::{self, ErrorCode};
use gcrypt::cipher::{self, Cipher};
use gcrypt::digest::{self, MessageDigest};
use gcrypt::sexp::{self, SExpression};
use gcrypt::pkey;

fn copy_slice<T: Copy>(src: &[T], dst: &mut [T]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
}

fn setup() -> Token {
    gcrypt::init().map(|mut x| {
        x.disable_secmem().enable_quick_random();
        x.finish()
    }).unwrap_or_else(|x| x)
}

#[test]
fn test_self_tests() {
    assert!(setup().run_self_tests());
}

fn check_cipher(token: Token, algo: cipher::Algorithm, mode: cipher::Mode, flags: cipher::Flags) {
    let key = b"0123456789abcdef.,;/[]{}-=ABCDEF";
    let mut plain = [0u8; 1040];
    copy_slice(b"foobar42FOOBAR17", &mut plain);
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

    let mut cipher = Cipher::new(token, algo, mode, flags).unwrap();
    cipher.set_key(&key[..algo.key_len()]).unwrap();

    let mut input = [0u8; 1040];
    let mut output = [0u8; 1040];
    cipher.encrypt(&plain, &mut output).unwrap();
    cipher.reset().unwrap();
    cipher.decrypt(&output, &mut input).unwrap();
    assert_eq!(&plain[..], &input[..]);

    cipher.reset().unwrap();
    copy_slice(&plain, &mut output);
    cipher.encrypt_inplace(&mut output).unwrap();
    cipher.reset().unwrap();
    cipher.decrypt_inplace(&mut output).unwrap();
    assert_eq!(&plain[..], &output[..]);
}

#[test]
fn test_block_ciphers() {
    let token = setup();

    let algos = [
        cipher::CIPHER_BLOWFISH,
        cipher::CIPHER_DES,
        cipher::CIPHER_3DES,
        cipher::CIPHER_CAST5,
        cipher::CIPHER_AES128,
        cipher::CIPHER_AES192,
        cipher::CIPHER_AES256,
        cipher::CIPHER_TWOFISH,
        cipher::CIPHER_TWOFISH128,
        cipher::CIPHER_SERPENT128,
        cipher::CIPHER_SERPENT192,
        cipher::CIPHER_SERPENT256,
        cipher::CIPHER_RFC2268_40,
        cipher::CIPHER_SEED,
        cipher::CIPHER_CAMELLIA128,
        cipher::CIPHER_CAMELLIA192,
        cipher::CIPHER_CAMELLIA256,
        cipher::CIPHER_IDEA,
        cipher::CIPHER_GOST28147,
    ];

    for &algo in algos.iter() {
        if !algo.is_available(token) {
            continue;
        }

        check_cipher(token, algo, cipher::MODE_ECB, cipher::Flags::empty());
        check_cipher(token, algo, cipher::MODE_CFB, cipher::Flags::empty());
        check_cipher(token, algo, cipher::MODE_OFB, cipher::Flags::empty());
        check_cipher(token, algo, cipher::MODE_CBC, cipher::Flags::empty());
        check_cipher(token, algo, cipher::MODE_CBC, cipher::FLAG_CBC_CTS);
        check_cipher(token, algo, cipher::MODE_CTR, cipher::Flags::empty());
        if algo.block_len() == 16 && token.check_version("1.6.0") {
            check_cipher(token, algo, cipher::MODE_GCM, cipher::Flags::empty());
        }
    }
}

#[test]
fn test_stream_ciphers() {
    let token = setup();

    let algos = [
        cipher::CIPHER_ARCFOUR,
        cipher::CIPHER_SALSA20,
        cipher::CIPHER_SALSA20R12,
    ];

    for &algo in algos.iter() {
        if !algo.is_available(token) {
            continue;
        }

        check_cipher(token, algo, cipher::MODE_STREAM, cipher::Flags::empty());
    }
}

#[test]
fn test_cipher_modes() {
    setup();
}

#[test]
fn test_bulk_cipher_modes() {
    let token = setup();

    let specs: &[(cipher::Algorithm, cipher::Mode, &[u8], &[u8], [u8; 20])] = &[

    (cipher::CIPHER_AES, cipher::MODE_CFB,
     b"abcdefghijklmnop", b"1234567890123456",
     [0x53, 0xda, 0x27, 0x3c, 0x78, 0x3d, 0x54, 0x66, 0x19, 0x63,
      0xd7, 0xe6, 0x20, 0x10, 0xcd, 0xc0, 0x5a, 0x0b, 0x06, 0xcc]),
    (cipher::CIPHER_AES192, cipher::MODE_CFB,
     b"abcdefghijklmnopABCDEFG\0", b"1234567890123456",
     [0xc7, 0xb1, 0xd0, 0x09, 0x95, 0x04, 0x34, 0x61, 0x2b, 0xd9,
      0xcb, 0xb3, 0xc7, 0xcb, 0xef, 0xea, 0x16, 0x19, 0x9b, 0x3e]),
    (cipher::CIPHER_AES256, cipher::MODE_CFB,
     b"abcdefghijklmnopABCDEFGHIJKLMNOP", b"1234567890123456",
     [0x31, 0xe1, 0x1f, 0x63, 0x65, 0x47, 0x8c, 0x3f, 0x53, 0xdb,
      0xd9, 0x4d, 0x91, 0x1d, 0x02, 0x9c, 0x05, 0x25, 0x58, 0x29]),
    (cipher::CIPHER_AES, cipher::MODE_CBC,
     b"abcdefghijklmnop", b"1234567890123456",
     [0xdc, 0x0c, 0xc2, 0xd9, 0x6b, 0x47, 0xf9, 0xeb, 0x06, 0xb4,
      0x2f, 0x6e, 0xec, 0x72, 0xbf, 0x55, 0x26, 0x7f, 0xa9, 0x97]),
    (cipher::CIPHER_AES192, cipher::MODE_CBC,
     b"abcdefghijklmnopABCDEFG\0", b"1234567890123456",
     [0x2b, 0x90, 0x9b, 0xe6, 0x40, 0xab, 0x6e, 0xc2, 0xc5, 0xb1,
      0x87, 0xf5, 0x43, 0x84, 0x7b, 0x04, 0x06, 0x47, 0xd1, 0x8f]),
    (cipher::CIPHER_AES256, cipher::MODE_CBC,
     b"abcdefghijklmnopABCDEFGHIJKLMNOP", b"1234567890123456",
     [0xaa, 0xa8, 0xdf, 0x03, 0xb0, 0xba, 0xc4, 0xe3, 0xc1, 0x02,
      0x38, 0x31, 0x8d, 0x86, 0xcb, 0x49, 0x6d, 0xad, 0xae, 0x01]),
    (cipher::CIPHER_AES, cipher::MODE_OFB,
     b"abcdefghijklmnop", b"1234567890123456",
     [0x65, 0xfe, 0xde, 0x48, 0xd0, 0xa1, 0xa6, 0xf9, 0x24, 0x6b,
      0x52, 0x5f, 0x21, 0x8a, 0x6f, 0xc7, 0x70, 0x3b, 0xd8, 0x4a]),
    (cipher::CIPHER_AES192, cipher::MODE_OFB,
     b"abcdefghijklmnopABCDEFG\0", b"1234567890123456",
     [0x59, 0x5b, 0x02, 0xa2, 0x88, 0xc0, 0xbe, 0x94, 0x43, 0xaa,
      0x39, 0xf6, 0xbd, 0xcc, 0x83, 0x99, 0xee, 0x00, 0xa1, 0x91]),
    (cipher::CIPHER_AES256, cipher::MODE_OFB,
     b"abcdefghijklmnopABCDEFGHIJKLMNOP", b"1234567890123456",
     [0x38, 0x8c, 0xe1, 0xe2, 0xbe, 0x67, 0x60, 0xe8, 0xeb, 0xce,
      0xd0, 0xc6, 0xaa, 0xd6, 0xf6, 0x26, 0x15, 0x56, 0xd0, 0x2b]),
    (cipher::CIPHER_AES, cipher::MODE_CTR,
     b"abcdefghijklmnop", b"1234567890123456",
     [0x9a, 0x48, 0x94, 0xd6, 0x50, 0x46, 0x81, 0xdb, 0x68, 0x34,
      0x3b, 0xc5, 0x9e, 0x66, 0x94, 0x81, 0x98, 0xa0, 0xf9, 0xff]),
    (cipher::CIPHER_AES192, cipher::MODE_CTR,
     b"abcdefghijklmnopABCDEFG\0", b"1234567890123456",
     [0x2c, 0x2c, 0xd3, 0x75, 0x81, 0x2a, 0x59, 0x07, 0xeb, 0x08,
      0xce, 0x28, 0x4c, 0x0c, 0x6a, 0xa8, 0x8f, 0xa3, 0x98, 0x7e]),
    (cipher::CIPHER_AES256, cipher::MODE_CTR,
     b"abcdefghijklmnopABCDEFGHIJKLMNOP", b"1234567890123456",
     [0x64, 0xce, 0x73, 0x03, 0xc7, 0x89, 0x99, 0x1f, 0xf1, 0xce,
      0xfe, 0xfb, 0xb9, 0x42, 0x30, 0xdf, 0xbb, 0x68, 0x6f, 0xd3]),
    (cipher::CIPHER_AES, cipher::MODE_ECB,
     b"abcdefghijklmnop", b"1234567890123456",
     [0x51, 0xae, 0xf5, 0xac, 0x22, 0xa0, 0xba, 0x11, 0xc5, 0xaa,
      0xb4, 0x70, 0x99, 0xce, 0x18, 0x08, 0x12, 0x9b, 0xb1, 0xc5]),
    (cipher::CIPHER_AES192, cipher::MODE_ECB,
     b"abcdefghijklmnopABCDEFG\0", b"1234567890123456",
     [0x57, 0x91, 0xea, 0x48, 0xd8, 0xbf, 0x9e, 0xc1, 0xae, 0x33,
      0xb3, 0xfd, 0xf7, 0x7a, 0xeb, 0x30, 0xb1, 0x62, 0x0d, 0x82]),
    (cipher::CIPHER_AES256, cipher::MODE_ECB,
     b"abcdefghijklmnopABCDEFGHIJKLMNOP", b"1234567890123456",
     [0x2d, 0x71, 0x54, 0xb9, 0xc5, 0x28, 0x76, 0xff, 0x76, 0xb5,
      0x99, 0x37, 0x99, 0x9d, 0xf7, 0x10, 0x6d, 0x86, 0x4f, 0x3f]),
    ];

    let mut buffer = vec![0u8; 1600];
    let mut output = vec![0u8; 1600];
    for spec in specs {
        for (i, b) in buffer.iter_mut().enumerate() {
            *b = ((i & 0xff) ^ ((i >> 8) & 0xff)) as u8;
        }

        let mut hde = Cipher::new(token, spec.0, spec.1, cipher::Flags::empty()).unwrap();
        let mut hdd = Cipher::new(token, spec.0, spec.1, cipher::Flags::empty()).unwrap();
        hde.set_key(spec.2).unwrap();
        hdd.set_key(spec.2).unwrap();
        hde.set_iv(spec.3).unwrap();
        hdd.set_iv(spec.3).unwrap();
        hde.encrypt(&buffer, &mut output).unwrap();

        let mut digest = MessageDigest::new(token, digest::MD_SHA1,
                                            digest::Flags::empty()).unwrap();
        digest.write(&output);
        assert_eq!(&spec.4, digest.get_only_digest().unwrap());
        hdd.decrypt_inplace(&mut output).unwrap();
        assert_eq!(&buffer, &output);
    }
}

fn check_digest(token: Token, algo: digest::Algorithm, data: &[u8], expected: &[u8]) {
    let mut digest = MessageDigest::new(token, algo, digest::Flags::empty()).unwrap();
    if data.starts_with(b"!") && data.len() == 1 {
        let aaa = [b'a'; 1000];
        for _ in 0..1000 {
            digest.write(&aaa);
        }
    } else {
        digest.write(data);
    }
    assert_eq!(Some(expected), digest.try_clone().unwrap().get_only_digest());
}

#[test]
fn test_digests() {
    let token = setup();

    let specs: &[(digest::Algorithm, &[u8], &[u8])] = &[
        (digest::MD_MD4, b"", b"\x31\xD6\xCF\xE0\xD1\x6A\xE9\x31\xB7\x3C\x59\xD7\xE0\xC0\x89\xC0"),
        (digest::MD_MD4, b"a",
         b"\xbd\xe5\x2c\xb3\x1d\xe3\x3e\x46\x24\x5e\x05\xfb\xdb\xd6\xfb\x24"),
        (digest::MD_MD4, b"message digest",
         b"\xd9\x13\x0a\x81\x64\x54\x9f\xe8\x18\x87\x48\x06\xe1\xc7\x01\x4b"),
        (digest::MD_MD5, b"", b"\xD4\x1D\x8C\xD9\x8F\x00\xB2\x04\xE9\x80\x09\x98\xEC\xF8\x42\x7E"),
        (digest::MD_MD5, b"a",
         b"\x0C\xC1\x75\xB9\xC0\xF1\xB6\xA8\x31\xC3\x99\xE2\x69\x77\x26\x61"),
        (digest::MD_MD5, b"abc",
         b"\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72"),
        (digest::MD_MD5, b"message digest",
         b"\xF9\x6B\x69\x7D\x7C\xB7\x93\x8D\x52\x5A\x2F\x31\xAA\xF1\x61\xD0"),
        (digest::MD_SHA1, b"abc",
         b"\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D"),
        (digest::MD_SHA1, b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         b"\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1"),
        (digest::MD_SHA1, b"!" /* kludge for b"a"*1000000 */ ,
         b"\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F"),
        (digest::MD_SHA224, b"abc",
         b"\x23\x09\x7d\x22\x34\x05\xd8\x22\x86\x42\xa4\x77\xbd\xa2\
           \x55\xb3\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7\xe3\x6c\x9d\xa7"),
        (digest::MD_SHA224, b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         b"\x75\x38\x8b\x16\x51\x27\x76\xcc\x5d\xba\x5d\xa1\xfd\x89\
           \x01\x50\xb0\xc6\x45\x5c\xb4\xf5\x8b\x19\x52\x52\x25\x25"),
        (digest::MD_SHA224, b"!",
         b"\x20\x79\x46\x55\x98\x0c\x91\xd8\xbb\xb4\xc1\xea\x97\x61\
           \x8a\x4b\xf0\x3f\x42\x58\x19\x48\xb2\xee\x4e\xe7\xad\x67"),
        (digest::MD_SHA256, b"abc",
         b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\
           \xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad"),
        (digest::MD_SHA256, b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         b"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\
           \xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1"),
        (digest::MD_SHA256, b"!",
         b"\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67\
           \xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0"),
        (digest::MD_SHA384, b"abc",
         b"\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07\
           \x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed\
           \x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7"),
        (digest::MD_SHA512, b"abc",
         b"\xDD\xAF\x35\xA1\x93\x61\x7A\xBA\xCC\x41\x73\x49\xAE\x20\x41\x31\
           \x12\xE6\xFA\x4E\x89\xA9\x7E\xA2\x0A\x9E\xEE\xE6\x4B\x55\xD3\x9A\
           \x21\x92\x99\x2A\x27\x4F\xC1\xA8\x36\xBA\x3C\x23\xA3\xFE\xEB\xBD\
           \x45\x4D\x44\x23\x64\x3C\xE8\x0E\x2A\x9A\xC9\x4F\xA5\x4C\xA4\x9F"),
        (digest::MD_RMD160, b"",
         b"\x9c\x11\x85\xa5\xc5\xe9\xfc\x54\x61\x28\x08\x97\x7e\xe8\xf5\x48\xb2\x25\x8d\x31"),
        (digest::MD_RMD160, b"a",
         b"\x0b\xdc\x9d\x2d\x25\x6b\x3e\xe9\xda\xae\x34\x7b\xe6\xf4\xdc\x83\x5a\x46\x7f\xfe"),
        (digest::MD_RMD160, b"abc",
         b"\x8e\xb2\x08\xf7\xe0\x5d\x98\x7a\x9b\x04\x4a\x8e\x98\xc6\xb0\x87\xf1\x5a\x0b\xfc"),
        (digest::MD_RMD160, b"message digest",
         b"\x5d\x06\x89\xef\x49\xd2\xfa\xe5\x72\xb8\x81\xb1\x23\xa8\x5f\xfa\x21\x59\x5f\x36"),
        (digest::MD_CRC32, b"", b"\x00\x00\x00\x00"),
        (digest::MD_CRC32, b"foo", b"\x8c\x73\x65\x21"),
        (digest::MD_CRC32_RFC1510, b"", b"\x00\x00\x00\x00"),
        (digest::MD_CRC32_RFC1510, b"foo", b"\x73\x32\xbc\x33"),
        (digest::MD_CRC32_RFC1510, b"test0123456789", b"\xb8\x3e\x88\xd6"),
        (digest::MD_CRC32_RFC1510, b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY", b"\xe3\x41\x80\xf7"),
        (digest::MD_CRC32_RFC1510, b"\x80", b"\xed\xb8\x83\x20"),
        (digest::MD_CRC24_RFC2440, b"", b"\xb7\x04\xce"),
        (digest::MD_CRC24_RFC2440, b"foo", b"\x4f\xc2\x55"),
        (digest::MD_TIGER, b"",
         b"\x24\xF0\x13\x0C\x63\xAC\x93\x32\x16\x16\x6E\x76\xB1\xBB\x92\x5F\
           \xF3\x73\xDE\x2D\x49\x58\x4E\x7A"),
        (digest::MD_TIGER, b"abc",
         b"\xF2\x58\xC1\xE8\x84\x14\xAB\x2A\x52\x7A\xB5\x41\xFF\xC5\xB8\xBF\
           \x93\x5F\x7B\x95\x1C\x13\x29\x51"),
        (digest::MD_TIGER, b"Tiger",
         b"\x9F\x00\xF5\x99\x07\x23\x00\xDD\x27\x6A\xBB\x38\xC8\xEB\x6D\xEC\
           \x37\x79\x0C\x11\x6F\x9D\x2B\xDF"),
        (digest::MD_TIGER, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
         b"\x87\xFB\x2A\x90\x83\x85\x1C\xF7\x47\x0D\x2C\xF8\x10\xE6\xDF\x9E\
           \xB5\x86\x44\x50\x34\xA5\xA3\x86"),
        (digest::MD_TIGER, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789",
         b"\x46\x7D\xB8\x08\x63\xEB\xCE\x48\x8D\xF1\xCD\x12\x61\x65\x5D\xE9\
           \x57\x89\x65\x65\x97\x5F\x91\x97"),
        (digest::MD_TIGER, b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham",
         b"\x0C\x41\x0A\x04\x29\x68\x86\x8A\x16\x71\xDA\x5A\x3F\xD2\x9A\x72\
           \x5E\xC1\xE4\x57\xD3\xCD\xB3\x03"),
        (digest::MD_TIGER,
         b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of \
           Fast Software Encryption 3, Cambridge.",
         b"\xEB\xF5\x91\xD5\xAF\xA6\x55\xCE\x7F\x22\x89\x4F\xF8\x7F\x54\xAC\
           \x89\xC8\x11\xB6\xB0\xDA\x31\x93"),
        (digest::MD_TIGER,
         b"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of \
           Fast Software Encryption 3, Cambridge, 1996.",
         b"\x3D\x9A\xEB\x03\xD1\xBD\x1A\x63\x57\xB2\x77\x4D\xFD\x6D\x5B\x24\
           \xDD\x68\x15\x1D\x50\x39\x74\xFC"),
        (digest::MD_TIGER,
         b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-\
           ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
         b"\x00\xB8\x3E\xB4\xE5\x34\x40\xC5\x76\xAC\x6A\xAE\xE0\xA7\x48\x58\
           \x25\xFD\x15\xE7\x0A\x59\xFF\xE4"),
        (digest::MD_TIGER1, b"",
         b"\x32\x93\xAC\x63\x0C\x13\xF0\x24\x5F\x92\xBB\xB1\x76\x6E\x16\x16\
           \x7A\x4E\x58\x49\x2D\xDE\x73\xF3"),
        (digest::MD_TIGER1, b"a",
         b"\x77\xBE\xFB\xEF\x2E\x7E\xF8\xAB\x2E\xC8\xF9\x3B\xF5\x87\xA7\xFC\
           \x61\x3E\x24\x7F\x5F\x24\x78\x09"),
        (digest::MD_TIGER1, b"abc",
         b"\x2A\xAB\x14\x84\xE8\xC1\x58\xF2\xBF\xB8\xC5\xFF\x41\xB5\x7A\x52\
           \x51\x29\x13\x1C\x95\x7B\x5F\x93"),
        (digest::MD_TIGER1, b"message digest",
         b"\xD9\x81\xF8\xCB\x78\x20\x1A\x95\x0D\xCF\x30\x48\x75\x1E\x44\x1C\
           \x51\x7F\xCA\x1A\xA5\x5A\x29\xF6"),
        (digest::MD_TIGER1, b"abcdefghijklmnopqrstuvwxyz",
         b"\x17\x14\xA4\x72\xEE\xE5\x7D\x30\x04\x04\x12\xBF\xCC\x55\x03\x2A\
           \x0B\x11\x60\x2F\xF3\x7B\xEE\xE9"),
        (digest::MD_TIGER1, b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         b"\x0F\x7B\xF9\xA1\x9B\x9C\x58\xF2\xB7\x61\x0D\xF7\xE8\x4F\x0A\xC3\
           \xA7\x1C\x63\x1E\x7B\x53\xF7\x8E"),
        (digest::MD_TIGER1, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         b"\x8D\xCE\xA6\x80\xA1\x75\x83\xEE\x50\x2B\xA3\x8A\x3C\x36\x86\x51\
           \x89\x0F\xFB\xCC\xDC\x49\xA8\xCC"),
        (digest::MD_TIGER1,
         b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         b"\x1C\x14\x79\x55\x29\xFD\x9F\x20\x7A\x95\x8F\x84\xC5\x2F\x11\xE8\
           \x87\xFA\x0C\xAB\xDF\xD9\x1B\xFD"),
        (digest::MD_TIGER1, b"!",
         b"\x6D\xB0\xE2\x72\x9C\xBE\xAD\x93\xD7\x15\xC6\xA7\xD3\x63\x02\xE9\
           \xB3\xCE\xE0\xD2\xBC\x31\x4B\x41"),
        (digest::MD_TIGER2, b"",
         b"\x44\x41\xBE\x75\xF6\x01\x87\x73\xC2\x06\xC2\x27\x45\x37\x4B\x92\
           \x4A\xA8\x31\x3F\xEF\x91\x9F\x41"),
        (digest::MD_TIGER2, b"a",
         b"\x67\xE6\xAE\x8E\x9E\x96\x89\x99\xF7\x0A\x23\xE7\x2A\xEA\xA9\x25\
           \x1C\xBC\x7C\x78\xA7\x91\x66\x36"),
        (digest::MD_TIGER2, b"abc",
         b"\xF6\x8D\x7B\xC5\xAF\x4B\x43\xA0\x6E\x04\x8D\x78\x29\x56\x0D\x4A\
           \x94\x15\x65\x8B\xB0\xB1\xF3\xBF"),
        (digest::MD_TIGER2, b"message digest",
         b"\xE2\x94\x19\xA1\xB5\xFA\x25\x9D\xE8\x00\x5E\x7D\xE7\x50\x78\xEA\
           \x81\xA5\x42\xEF\x25\x52\x46\x2D"),
        (digest::MD_TIGER2, b"abcdefghijklmnopqrstuvwxyz",
         b"\xF5\xB6\xB6\xA7\x8C\x40\x5C\x85\x47\xE9\x1C\xD8\x62\x4C\xB8\xBE\
           \x83\xFC\x80\x4A\x47\x44\x88\xFD"),
        (digest::MD_TIGER2, b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         b"\xA6\x73\x7F\x39\x97\xE8\xFB\xB6\x3D\x20\xD2\xDF\x88\xF8\x63\x76\
           \xB5\xFE\x2D\x5C\xE3\x66\x46\xA9"),
        (digest::MD_TIGER2, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         b"\xEA\x9A\xB6\x22\x8C\xEE\x7B\x51\xB7\x75\x44\xFC\xA6\x06\x6C\x8C\
           \xBB\x5B\xBA\xE6\x31\x95\x05\xCD"),
        (digest::MD_TIGER2,
         b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
         b"\xD8\x52\x78\x11\x53\x29\xEB\xAA\x0E\xEC\x85\xEC\xDC\x53\x96\xFD\
           \xA8\xAA\x3A\x58\x20\x94\x2F\xFF"),
        (digest::MD_TIGER2, b"!",
         b"\xE0\x68\x28\x1F\x06\x0F\x55\x16\x28\xCC\x57\x15\xB9\xD0\x22\x67\
           \x96\x91\x4D\x45\xF7\x71\x7C\xF4"),
        (digest::MD_WHIRLPOOL, b"",
         b"\x19\xFA\x61\xD7\x55\x22\xA4\x66\x9B\x44\xE3\x9C\x1D\x2E\x17\x26\
           \xC5\x30\x23\x21\x30\xD4\x07\xF8\x9A\xFE\xE0\x96\x49\x97\xF7\xA7\
           \x3E\x83\xBE\x69\x8B\x28\x8F\xEB\xCF\x88\xE3\xE0\x3C\x4F\x07\x57\
           \xEA\x89\x64\xE5\x9B\x63\xD9\x37\x08\xB1\x38\xCC\x42\xA6\x6E\xB3"),
        (digest::MD_WHIRLPOOL, b"a",
         b"\x8A\xCA\x26\x02\x79\x2A\xEC\x6F\x11\xA6\x72\x06\x53\x1F\xB7\xD7\
           \xF0\xDF\xF5\x94\x13\x14\x5E\x69\x73\xC4\x50\x01\xD0\x08\x7B\x42\
           \xD1\x1B\xC6\x45\x41\x3A\xEF\xF6\x3A\x42\x39\x1A\x39\x14\x5A\x59\
           \x1A\x92\x20\x0D\x56\x01\x95\xE5\x3B\x47\x85\x84\xFD\xAE\x23\x1A"),
        (digest::MD_WHIRLPOOL, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
         b"\xDC\x37\xE0\x08\xCF\x9E\xE6\x9B\xF1\x1F\x00\xED\x9A\xBA\x26\x90\
           \x1D\xD7\xC2\x8C\xDE\xC0\x66\xCC\x6A\xF4\x2E\x40\xF8\x2F\x3A\x1E\
           \x08\xEB\xA2\x66\x29\x12\x9D\x8F\xB7\xCB\x57\x21\x1B\x92\x81\xA6\
           \x55\x17\xCC\x87\x9D\x7B\x96\x21\x42\xC6\x5F\x5A\x7A\xF0\x14\x67"),
        (digest::MD_WHIRLPOOL, b"!",
         b"\x0C\x99\x00\x5B\xEB\x57\xEF\xF5\x0A\x7C\xF0\x05\x56\x0D\xDF\x5D\
           \x29\x05\x7F\xD8\x6B\x20\xBF\xD6\x2D\xEC\xA0\xF1\xCC\xEA\x4A\xF5\
           \x1F\xC1\x54\x90\xED\xDC\x47\xAF\x32\xBB\x2B\x66\xC3\x4F\xF9\xAD\
           \x8C\x60\x08\xAD\x67\x7F\x77\x12\x69\x53\xB2\x26\xE4\xED\x8B\x01"),
        (digest::MD_GOSTR3411_94, b"This is message, length=32 bytes",
         b"\xB1\xC4\x66\xD3\x75\x19\xB8\x2E\x83\x19\x81\x9F\xF3\x25\x95\xE0\
           \x47\xA2\x8C\xB6\xF8\x3E\xFF\x1C\x69\x16\xA8\x15\xA6\x37\xFF\xFA"),
        (digest::MD_GOSTR3411_94, b"Suppose the original message has length = 50 bytes",
         b"\x47\x1A\xBA\x57\xA6\x0A\x77\x0D\x3A\x76\x13\x06\x35\xC1\xFB\xEA\
           \x4E\xF1\x4D\xE5\x1F\x78\xB4\xAE\x57\xDD\x89\x3B\x62\xF5\x52\x08"),
        (digest::MD_GOSTR3411_94, b"",
         b"\xCE\x85\xB9\x9C\xC4\x67\x52\xFF\xFE\xE3\x5C\xAB\x9A\x7B\x02\x78\
           \xAB\xB4\xC2\xD2\x05\x5C\xFF\x68\x5A\xF4\x91\x2C\x49\x49\x0F\x8D"),
        (digest::MD_GOSTR3411_94, b"!",
         b"\x5C\x00\xCC\xC2\x73\x4C\xDD\x33\x32\xD3\xD4\x74\x95\x76\xE3\xC1\
           \xA7\xDB\xAF\x0E\x7E\xA7\x4E\x9F\xA6\x02\x41\x3C\x90\xA1\x29\xFA"),
        (digest::MD_STRIBOG512, b"012345678901234567890123456789012345678901234567890123456789012",
         b"\x1b\x54\xd0\x1a\x4a\xf5\xb9\xd5\xcc\x3d\x86\xd6\x8d\x28\x54\x62\
           \xb1\x9a\xbc\x24\x75\x22\x2f\x35\xc0\x85\x12\x2b\xe4\xba\x1f\xfa\
           \x00\xad\x30\xf8\x76\x7b\x3a\x82\x38\x4c\x65\x74\xf0\x24\xc3\x11\
           \xe2\xa4\x81\x33\x2b\x08\xef\x7f\x41\x79\x78\x91\xc1\x64\x6f\x48"),
        (digest::MD_STRIBOG256, b"012345678901234567890123456789012345678901234567890123456789012",
         b"\x9d\x15\x1e\xef\xd8\x59\x0b\x89\xda\xa6\xba\x6c\xb7\x4a\xf9\x27\
           \x5d\xd0\x51\x02\x6b\xb1\x49\xa4\x52\xfd\x84\xe5\xe5\x7b\x55\x00"),
        (digest::MD_STRIBOG512,
         b"\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee\xe6\xe8\
           \x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20\xf1\x20\xec\xee\
           \xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20\xed\xe0\x20\xf5\xf0\xe0\
           \xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
         b"\x1e\x88\xe6\x22\x26\xbf\xca\x6f\x99\x94\xf1\xf2\xd5\x15\x69\xe0\
           \xda\xf8\x47\x5a\x3b\x0f\xe6\x1a\x53\x00\xee\xe4\x6d\x96\x13\x76\
           \x03\x5f\xe8\x35\x49\xad\xa2\xb8\x62\x0f\xcd\x7c\x49\x6c\xe5\xb3\
           \x3f\x0c\xb9\xdd\xdc\x2b\x64\x60\x14\x3b\x03\xda\xba\xc9\xfb\x28"),
        (digest::MD_STRIBOG256,
         b"\xd1\xe5\x20\xe2\xe5\xf2\xf0\xe8\x2c\x20\xd1\xf2\xf0\xe8\xe1\xee\xe6\xe8\
           \x20\xe2\xed\xf3\xf6\xe8\x2c\x20\xe2\xe5\xfe\xf2\xfa\x20\xf1\x20\xec\xee\
           \xf0\xff\x20\xf1\xf2\xf0\xe5\xeb\xe0\xec\xe8\x20\xed\xe0\x20\xf5\xf0\xe0\
           \xe1\xf0\xfb\xff\x20\xef\xeb\xfa\xea\xfb\x20\xc8\xe3\xee\xf0\xe5\xe2\xfb",
         b"\x9d\xd2\xfe\x4e\x90\x40\x9e\x5d\xa8\x7f\x53\x97\x6d\x74\x05\xb0\
           \xc0\xca\xc6\x28\xfc\x66\x9a\x74\x1d\x50\x06\x3c\x55\x7e\x8f\x50"),
            ];

    for spec in specs {
        if !spec.0.is_available(token) {
            continue;
        }

        check_digest(token, spec.0, spec.1, spec.2);
    }
}

fn check_hmac(token: Token, algo: digest::Algorithm, data: &[u8], key: &[u8], expected: &[u8]) {
    let mut hmac = MessageDigest::new(token, algo, digest::FLAG_HMAC).unwrap();
    hmac.set_key(key).unwrap();
    hmac.write(data);
    assert_eq!(Some(expected), hmac.try_clone().unwrap().get_only_digest());
}

#[test]
fn test_hmacs() {
    let token = setup();

    let specs: &[(digest::Algorithm, &[u8], &[u8], &[u8])] = &[
        (digest::MD_MD5, b"what do ya want for nothing?", b"Jefe",
         b"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38"),
        (digest::MD_MD5,
         b"Hi There",
         b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
         b"\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d"),
        (digest::MD_MD5,
         b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd",
         b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
         b"\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6"),
        (digest::MD_MD5,
         b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd",
         b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
           \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
         b"\x69\x7e\xaf\x0a\xca\x3a\x3a\xea\x3a\x75\x16\x47\x46\xff\xaa\x79"),
        (digest::MD_MD5, b"Test With Truncation",
         b"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
         b"\x56\x46\x1e\xf2\x34\x2e\xdc\x00\xf9\xba\xb9\x95\x69\x0e\xfd\x4c"),
        (digest::MD_MD5, b"Test Using Larger Than Block-Size Key - Hash Key First",
         b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa",
         b"\x6b\x1a\xb7\xfe\x4b\xd7\xbf\x8f\x0b\x62\xe6\xce\x61\xb9\xd0\xcd"),
        (digest::MD_MD5,
         b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
         b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
           \xaa\xaa\xaa\xaa\xaa",
         b"\x6f\x63\x0f\xad\x67\xcd\xa0\xee\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e"),
        (digest::MD_SHA256, b"what do ya want for nothing?", b"Jefe",
         b"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\
           \x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43"),
        (digest::MD_SHA256,
         b"Hi There",
         b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
           \x0b\x0b\x0b",
         b"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\
           \x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7"),
        (digest::MD_SHA256,
         b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd",
         b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\
           \xAA\xAA\xAA\xAA",
         b"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\
           \x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe"),
        (digest::MD_SHA256,
         b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd",
         b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
           \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
         b"\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\
           \x3a\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b"),
        (digest::MD_SHA256,
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
           \x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54"),
        (digest::MD_SHA256,
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
           \xbf\xdc\x63\x64\x4f\x07\x13\x93\x8a\x7f\x51\x53\x5c\x3a\x35\xe2"),
        (digest::MD_SHA224, b"what do ya want for nothing?", b"Jefe",
         b"\xa3\x0e\x01\x09\x8b\xc6\xdb\xbf\x45\x69\x0f\x3a\x7e\x9e\x6d\x0f\
           \x8b\xbe\xa2\xa3\x9e\x61\x48\x00\x8f\xd0\x5e\x44"),
        (digest::MD_SHA224,
         b"Hi There",
         b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
           \x0b\x0b\x0b",
         b"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\
           \xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22"),
        (digest::MD_SHA224,
         b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd",
         b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\
           \xAA\xAA\xAA\xAA",
         b"\x7f\xb3\xcb\x35\x88\xc6\xc1\xf6\xff\xa9\x69\x4d\x7d\x6a\xd2\x64\
           \x93\x65\xb0\xc1\xf6\x5d\x69\xd1\xec\x83\x33\xea"),
        (digest::MD_SHA224,
         b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd",
         b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
           \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
         b"\x6c\x11\x50\x68\x74\x01\x3c\xac\x6a\x2a\xbc\x1b\xb3\x82\x62\
           \x7c\xec\x6a\x90\xd8\x6e\xfc\x01\x2d\xe7\xaf\xec\x5a"),
        (digest::MD_SHA224,
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
           \xd4\x99\xf1\x12\xf2\xd2\xb7\x27\x3f\xa6\x87\x0e"),
        (digest::MD_SHA224,
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
           \x94\x67\x70\xdb\x9c\x2b\x95\xc9\xf6\xf5\x65\xd1"),
        (digest::MD_SHA384, b"what do ya want for nothing?", b"Jefe",
         b"\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b\
           \x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e\
           \x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49"),
        (digest::MD_SHA384,
         b"Hi There",
         b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
           \x0b\x0b\x0b",
         b"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\
           \xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\
           \x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6"),
        (digest::MD_SHA384,
         b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd",
         b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\
           \xAA\xAA\xAA\xAA",
         b"\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f\
           \x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66\x14\x4b\
           \x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27"),
        (digest::MD_SHA384,
         b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd",
         b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
           \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
         b"\x3e\x8a\x69\xb7\x78\x3c\x25\x85\x19\x33\xab\x62\x90\xaf\x6c\xa7\
           \x7a\x99\x81\x48\x08\x50\x00\x9c\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e\
           \x68\x01\xdd\x23\xc4\xa7\xd6\x79\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb"),
        (digest::MD_SHA384,
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
           \x0c\x2e\xf6\xab\x40\x30\xfe\x82\x96\x24\x8d\xf1\x63\xf4\x49\x52"),
        (digest::MD_SHA384,
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
           \xa6\x78\xcc\x31\xe7\x99\x17\x6d\x38\x60\xe6\x11\x0c\x46\x52\x3e"),
        (digest::MD_SHA512, b"what do ya want for nothing?", b"Jefe",
         b"\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3\
           \x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54\
           \x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd\
           \xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37"),
        (digest::MD_SHA512,
         b"Hi There",
         b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
           \x0b\x0b\x0b",
         b"\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\
           \x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\
           \xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\
           \xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54"),
        (digest::MD_SHA512,
         b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
           \xdd\xdd\xdd\xdd\xdd",
         b"\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\
           \xAA\xAA\xAA\xAA",
         b"\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9\
           \xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39\
           \xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07\
           \xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb" ),
        (digest::MD_SHA512,
         b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
           \xcd\xcd\xcd\xcd\xcd",
         b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
           \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
         b"\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7\
           \xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb\
           \xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63\
           \xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd"),
        (digest::MD_SHA512,
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
           \x95\xe6\x4f\x73\xf6\x3f\x0a\xec\x8b\x91\x5a\x98\x5d\x78\x65\x98"),
        (digest::MD_SHA512,
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
           \x13\x46\x76\xfb\x6d\xe0\x44\x60\x65\xc9\x74\x40\xfa\x8c\x6a\x58"),
    ];

    for spec in specs {
        if !spec.0.is_available(token) {
            continue;
        }

        check_hmac(token, spec.0, spec.1, spec.2, spec.3);
    }
}

const FLAG_CRYPT: usize = 1;
const FLAG_SIGN: usize = 2;
const FLAG_GRIP: usize = 4;

fn verify_signature(pkey: &SExpression, hash: &SExpression, bad_hash: &SExpression,
                    sig: &SExpression) {
    assert_eq!(pkey.verify(sig, hash).err(), None);
    assert_eq!(pkey.verify(sig, bad_hash).err().map_or(0, |e| e.code()),
               error::GPG_ERR_BAD_SIGNATURE);
}

fn check_pkey_sign(algo: pkey::Algorithm, skey: &SExpression, pkey: &SExpression) {
    let specs: &[(&[u8], Option<pkey::Algorithm>, ErrorCode)] = &[
        (b"(data\n (flags pkcs1)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
         Some(pkey::PK_RSA), 0),
        (b"(data\n (flags oaep)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
         None, error::GPG_ERR_CONFLICT),
        (b"(data\n (flags pkcs1)\n\
            (hash oid.1.3.14.3.2.29 \
                  #11223344556677889900AABBCCDDEEFF10203040#))\n",
         Some(pkey::PK_RSA), 0),
        (b"(data\n (flags )\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
         None, error::GPG_ERR_CONFLICT),
        (b"(data\n (flags pkcs1)\n\
            (hash foo #11223344556677889900AABBCCDDEEFF10203040#))\n",
         Some(pkey::PK_RSA), error::GPG_ERR_DIGEST_ALGO),
        (b"(data\n (flags )\n (value #11223344556677889900AA#))\n",
         None, 0),
        (b"(data\n (flags )\n (value #0090223344556677889900AA#))\n",
         None, 0),
        (b"(data\n (flags raw)\n (value #11223344556677889900AA#))\n",
         None, 0),
        (b"(data\n (flags pkcs1)\n (value #11223344556677889900AA#))\n",
         Some(pkey::PK_RSA), error::GPG_ERR_CONFLICT),
        (b"(data\n (flags raw foo)\n (value #11223344556677889900AA#))\n",
         None, error::GPG_ERR_INV_FLAG),
        (b"(data\n (flags pss)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
         Some(pkey::PK_RSA), 0),
        (b"(data\n (flags pss)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#)\n\
            (random-override #4253647587980912233445566778899019283747#))\n",
         Some(pkey::PK_RSA), 0),
    ];

    let bad_hash = SExpression::from_bytes(
        &b"(data\n (flags pkcs1)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203041#))\n"[..]
    ).unwrap();

    for spec in specs {
        if spec.1.is_some() && (spec.1 != Some(algo)) {
            continue;
        }

        let hash = SExpression::from_bytes(spec.0).unwrap();
        let sig = match skey.sign(&hash) {
            Ok(s) => s,
            Err(e) => {
                assert_eq!(spec.2, e.code());
                return;
            },
        };
        verify_signature(pkey, &hash, &bad_hash, &sig);
    }
}

fn check_pkey_sign_ecdsa(skey: &SExpression, pkey: &SExpression) {
    let specs: &[(usize, &[u8], ErrorCode, &[u8])] = &[
        (192,
         b"(data (flags raw)\n\
            (value #00112233445566778899AABBCCDDEEFF0001020304050607#))", 0,
         b"(data (flags raw)\n\
           (value #80112233445566778899AABBCCDDEEFF0001020304050607#))"),
        (256,
         b"(data (flags raw)\n\
            (value #00112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F#))", 0,
         b"(data (flags raw)\n\
            (value #80112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F#))"),
        (256,
         b"(data (flags raw)\n\
            (hash sha256 #00112233445566778899AABBCCDDEEFF\
                          000102030405060708090A0B0C0D0E0F#))", 0,
         b"(data (flags raw)\n\
            (hash sha256 #80112233445566778899AABBCCDDEEFF\
                          000102030405060708090A0B0C0D0E0F#))"),
        (256,
         b"(data (flags gost)\n\
            (value #00112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F#))", 0,
         b"(data (flags gost)\n\
            (value #80112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F#))"),
        (512,
         b"(data (flags gost)\n\
            (value #00112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F\
                    000102030405060708090A0B0C0D0E0F\
                    000102030405060708090A0B0C0D0E0F#))", 0,
         b"(data (flags gost)\n\
            (value #80112233445566778899AABBCCDDEEFF\
                    000102030405060708090A0B0C0D0E0F\
                    000102030405060708090A0B0C0D0E0F\
                    000102030405060708090A0B0C0D0E0F#))"),
             ];

    let nbits = skey.num_bits();
    for spec in specs {
        if Some(spec.0) != nbits {
            continue;
        }

        let hash = SExpression::from_bytes(spec.1).unwrap();
        let bad_hash = SExpression::from_bytes(spec.3).unwrap();
        let sig = match skey.sign(&hash) {
            Ok(s) => s,
            Err(e) => {
                assert_eq!(spec.2, e.code());
                return;
            },
        };
        verify_signature(pkey, &hash, &bad_hash, &sig);
    }
}

fn check_pkey_crypt(algo: pkey::Algorithm, skey: &SExpression, pkey: &SExpression) {
    let specs: &[(Option<pkey::Algorithm>, &[u8], &[u8], bool, ErrorCode, ErrorCode, bool)] = &[
        (Some(pkey::PK_RSA),
         b"(data\n (flags pkcs1)\n\
            (value #11223344556677889900AA#))\n",
         b"", false, 0, 0, false),
        (Some(pkey::PK_RSA),
         b"(data\n (flags pkcs1)\n\
            (value #11223344556677889900AA#))\n",
         b"(flags pkcs1)", true, 0, 0, false),
        (Some(pkey::PK_RSA),
         b"(data\n (flags oaep)\n\
            (value #11223344556677889900AA#))\n",
         b"(flags oaep)", true, 0, 0, false),
        (Some(pkey::PK_RSA),
         b"(data\n (flags oaep)\n (hash-algo sha1)\n\
            (value #11223344556677889900AA#))\n",
         b"(flags oaep)(hash-algo sha1)", true, 0, 0, false),
        (Some(pkey::PK_RSA),
         b"(data\n (flags oaep)\n (hash-algo sha1)\n (label \"test\")\n\
            (value #11223344556677889900AA#))\n",
         b"(flags oaep)(hash-algo sha1)(label \"test\")", true, 0, 0, false),
        (Some(pkey::PK_RSA),
         b"(data\n (flags oaep)\n (hash-algo sha1)\n (label \"test\")\n\
            (value #11223344556677889900AA#)\n\
            (random-override #4253647587980912233445566778899019283747#))\n",
         b"(flags oaep)(hash-algo sha1)(label \"test\")", true, 0, 0, false),
        (None,
         b"(data\n (flags )\n (value #11223344556677889900AA#))\n",
         b"", true, 0, 0, false),
        (None,
         b"(data\n (flags )\n (value #0090223344556677889900AA#))\n",
         b"", true, 0, 0, false),
        (None,
         b"(data\n (flags raw)\n (value #11223344556677889900AA#))\n",
         b"", true, 0, 0, false),
        (Some(pkey::PK_RSA),
         b"(data\n (flags pkcs1)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
         b"", false, error::GPG_ERR_CONFLICT, 0, false),
        (None,
         b"(data\n (flags raw foo)\n\
            (hash sha1 #11223344556677889900AABBCCDDEEFF10203040#))\n",
         b"", false, error::GPG_ERR_INV_FLAG, 0, false),
        (None,
         b"(data\n (flags raw)\n (value #11223344556677889900AA#))\n",
         b"(flags oaep)", true, 0, error::GPG_ERR_ENCODING_PROBLEM, true),
        (Some(pkey::PK_RSA),
         b"(data\n (flags oaep)\n (value #11223344556677889900AA#))\n",
         b"(flags pkcs1)", true, 0, error::GPG_ERR_ENCODING_PROBLEM, true),
        (None, b"(data\n (flags pss)\n (value #11223344556677889900AA#))\n",
         b"", false, error::GPG_ERR_CONFLICT, 0, false),
    ];

    for spec in specs {
        if spec.0.is_some() && (spec.0 != Some(algo)) {
            continue;
        }

        let data = SExpression::from_bytes(spec.1).unwrap();
        let cipher = {
            let cipher = match pkey.encrypt(&data) {
                Ok(s) => s,
                Err(e) => {
                    assert_eq!(spec.4, e.code());
                    return;
                },
            };

            if !spec.2.is_empty() {
                let hint = SExpression::from_bytes(spec.2).unwrap()
                    .to_bytes(sexp::Format::Canonical);
                let len = cipher.len_encoded(sexp::Format::Canonical) + hint.len();
                let mut buffer = vec![0u8; len];
                cipher.encode(sexp::Format::Canonical, &mut buffer[hint.len()..]);
                for i in (0..10).rev() {
                    buffer[i] = buffer[i + hint.len()];
                }
                copy_slice(&hint, &mut buffer[10..(10 + hint.len())]);
                SExpression::from_bytes(&buffer).unwrap()
            } else {
                cipher
            }
        };
        let plain = match skey.decrypt(&cipher) {
            Ok(s) => s,
            Err(e) => {
                assert_eq!(spec.5, e.code());
                return;
            },
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

fn check_pkey(algo: pkey::Algorithm, flags: usize, skey: &SExpression,
              pkey: &SExpression, grip: &[u8]) {
    if (flags & FLAG_SIGN) == FLAG_SIGN {
        if algo == pkey::PK_ECDSA {
            check_pkey_sign_ecdsa(skey, pkey);
        } else {
            check_pkey_sign(algo, skey, pkey);
        }
    }
    if (flags & FLAG_CRYPT) == FLAG_CRYPT {
        check_pkey_crypt(algo, skey, pkey);
    }
    if (flags & FLAG_GRIP) == FLAG_GRIP {
        assert_eq!(grip, skey.key_grip().unwrap());
        assert_eq!(grip, pkey.key_grip().unwrap());
    }
}

#[test]
fn test_pkey() {
  let token = setup();

  let keys: &[(pkey::Algorithm, usize, (&[u8], &[u8], &[u8]))] = &[
      (pkey::PK_RSA, FLAG_CRYPT | FLAG_SIGN,
       (b"(private-key\n\
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
          \xa2\x5d\x3d\x69\xf8\x6d\x37\xa4\xf9\x39")),
      (pkey::PK_DSA, FLAG_SIGN,
       (b"(private-key\n\
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
          \x4a\xa6\xf9\xeb\x23\xbf\xa9\x12\x2d\x5b")),
      (pkey::PK_ELG, FLAG_SIGN | FLAG_CRYPT,
       (b"(private-key\n\
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
          \x4f\xba\x06\xf8\x78\x09\xbc\x1e\x20\xe5")),
      (pkey::PK_ECDSA, FLAG_SIGN,
       (b"(private-key\n\
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
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")),
      (pkey::PK_ECDSA, FLAG_SIGN,
       (b"(private-key\n\
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
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")),
      (pkey::PK_ECDSA, FLAG_SIGN,
       (b"(private-key\n\
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
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")),
      (pkey::PK_ECDSA, FLAG_SIGN,
       (b"(private-key\n\
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
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")),
      (pkey::PK_ECDSA, FLAG_SIGN,
       (b"(private-key\n\
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
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")),
      (pkey::PK_ECDSA, FLAG_SIGN,
       (b"(private-key\n\
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
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")),
      (pkey::PK_ECDSA, FLAG_SIGN,
       (b"(private-key\n\
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
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")),
  ];
  for &(algo, flags, key) in keys {
    if !algo.is_available(token) {
        continue;
    }
    let skey = SExpression::from_bytes(key.0).unwrap();
    let pkey = SExpression::from_bytes(key.1).unwrap();
    check_pkey(algo, flags, &skey, &pkey, key.2);
  }

  let key_spec = SExpression::from_bytes(
      &b"(genkey (rsa (nbits 4:1024)))").unwrap();
  let key = key_spec.generate_key().unwrap();
  let pkey = key.find_token("public-key").unwrap();
  let skey = key.find_token("private-key").unwrap();
  check_pkey(pkey::PK_RSA, FLAG_SIGN | FLAG_CRYPT, &skey, &pkey, b"");
}
