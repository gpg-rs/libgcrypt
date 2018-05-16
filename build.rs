use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

fn main() {
    let (mut major, mut minor) = if let Ok(v) = env::var("DEP_GCRYPT_VERSION") {
        let mut components = v.trim().split('.').scan((), |_, x| x.parse::<u8>().ok()).fuse();
        match (components.next(), components.next()) {
            (Some(major), Some(minor)) => (major, minor),
            _ => (1, 5),
        }
    } else {
        (1, 5)
    };

    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut output = File::create(path.join("version.rs")).unwrap();
    writeln!(output, "pub const MIN_VERSION: &str = \"{}.{}.0\\0\";", major, minor).unwrap();
    writeln!(
        output,
        "#[macro_export]\nmacro_rules! require_gcrypt_ver {{\n\
         ($ver:tt => {{ $($t:tt)* }}) => (require_gcrypt_ver! {{ $ver => {{ $($t)* }} else {{}} }});"
    ).unwrap();
    loop {
        writeln!(
            output,
            "(({0},{1}) => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($t)*);",
            major, minor
        ).unwrap();

        if minor == 0 {
            break;
        }
        minor -= 1;
    }
    major -= 1;

    loop {
        writeln!(
            output,
            "(({0},$ver:tt) => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($t)*);",
            major
        ).unwrap();

        if major == 0 {
            break;
        }
        major -= 1;
    }
    writeln!(
        output,
        "($ver:tt => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($u)*);\n}}"
    ).unwrap();
}
