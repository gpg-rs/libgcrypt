use std::env;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

fn main() -> Result<(), Box<Error>> {
    let (major, minor) = if let Ok(v) = env::var("DEP_GCRYPT_VERSION") {
        let mut components = v
            .trim()
            .split('.')
            .scan((), |_, x| x.parse::<u8>().ok())
            .fuse();
        match (components.next(), components.next()) {
            (Some(major), Some(minor)) => (major, minor),
            _ => (1, 5),
        }
    } else {
        (1, 5)
    };

    let path = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut output = File::create(path.join("version.rs"))?;
    writeln!(
        output,
        "pub const MIN_VERSION: &str = \"{}.{}.0\\0\";",
        major, minor
    )?;
    writeln!(
        output,
        "#[macro_export]\nmacro_rules! require_gcrypt_ver {{\n\
         ($ver:tt => {{ $($t:tt)* }}) => (require_gcrypt_ver! {{ $ver => {{ $($t)* }} else {{}} }});"
    )?;
    for i in 0..=minor {
        writeln!(
            output,
            "(({0},{1}) => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($t)*);",
            major, i
        )?;
    }

    for i in 0..major {
        writeln!(
            output,
            "(({0},$ver:tt) => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($t)*);",
            i
        )?;
    }
    writeln!(
        output,
        "($ver:tt => {{ $($t:tt)* }} else {{ $($u:tt)* }}) => ($($u)*);\n}}"
    )?;
    Ok(())
}
