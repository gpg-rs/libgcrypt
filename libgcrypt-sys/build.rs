#[macro_use]
extern crate cfg_if;
#[cfg(feature = "shim")]
extern crate gcc;

use std::cmp::Ordering;
use std::env;
use std::ffi::OsString;
use std::iter;
use std::path::Path;
use std::process::Command;
use std::str;

cfg_if! {
    if #[cfg(feature = "v1_7_0")] {
        const TARGET_VERSION: &'static str = "1.7.0";
    } else if #[cfg(feature = "v1_6_0")] {
        const TARGET_VERSION: &'static str = "1.6.0";
    } else {
        const TARGET_VERSION: &'static str = "1.5.0";
    }
}

fn main() {
    let mut include_dirs = Vec::new();
    if let Ok(lib) = env::var("LIBGCRYPT_LIB") {
        if let Some(include) = env::var_os("LIBGCRYPT_INCLUDE_DIR") {
            include_dirs.push(include);
        }

        let mode = match env::var_os("LIBGCRYPT_STATIC") {
            Some(_) => "static",
            _ => "dylib",
        };
        println!("cargo:rustc-link-lib={0}={1}", mode, lib);
    } else {
        let path = env::var_os("LIBGCRYPT_CONFIG").unwrap_or("libgcrypt-config".into());
        let mut command = Command::new(&path);
        command.arg("--version");
        let output = command.output().unwrap();
        if !output.status.success() {
            panic!("`{:?}` did not exit successfully: {}", command, output.status);
        }
        test_version(&str::from_utf8(&output.stdout).unwrap());

        let mut command = Command::new(&path);
        command.args(&["--cflags", "--libs"]);
        let output = command.output().unwrap();
        if !output.status.success() {
            panic!("`{:?}` did not exit successfully: {}", command, output.status);
        }
        parse_config_output(&str::from_utf8(&output.stdout).unwrap(), &mut include_dirs);
    }

    build_shim(&include_dirs);
}

fn test_version(version: &str) {
    let version = version.trim();
    for (x, y) in TARGET_VERSION.split('.').zip(version.split('.').chain(iter::repeat("0"))) {
        let (x, y): (u8, u8) = (x.parse().unwrap(), y.parse().unwrap());
        match x.cmp(&y) {
            Ordering::Less => break,
            Ordering::Greater => {
                panic!("gcrypt version `{}` is less than requested `{}`",
                       version, TARGET_VERSION)
            }
            _ => (),
        }
    }
}

fn parse_config_output(output: &str, include_dirs: &mut Vec<OsString>) {
    let parts = output.split(|c: char| c.is_whitespace()).filter_map(|p| {
        if p.len() > 2 {
            Some(p.split_at(2))
        } else {
            None
        }
    });

    for (flag, val) in parts {
        match flag {
            "-I" => include_dirs.push(val.into()),
            "-L" => {
                println!("cargo:rustc-link-search=native={}", val);
            },
            "-F" => {
                println!("cargo:rustc-link-search=framework={}", val);
            },
            "-l" => {
                println!("cargo:rustc-link-lib={}", val);
            },
            _ => ()
        }
    }
}

#[cfg(feature = "shim")]
fn build_shim<P: AsRef<Path>>(include_dirs: &[P]) {
    let mut config = gcc::Config::new();
    for path in include_dirs.iter() {
        config.include(path);
    }
    config.flag("-Wno-deprecated-declarations").file("shim.c").compile("libgcrypt_shim.a");
}

#[cfg(not(feature = "shim"))]
fn build_shim<P: AsRef<Path>>(_include_dirs: &[P]) { }
