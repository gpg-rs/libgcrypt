#[cfg(feature = "shim")]
extern crate gcc;

use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::str;

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
        println!("cargo:rustc-flags=-l {0}={1}", mode, lib);
    } else {
        let mut command = Command::new(env::var_os("LIBGCRYPT_CONFIG")
                .unwrap_or("libgcrypt-config".into()));
        command.args(&["--cflags", "--libs"]);

        let output = command.output().unwrap();
        if !output.status.success() {
            panic!("`{:?}` did not exit successfully: {}", command, output.status);
        }
        parse_config_output(&str::from_utf8(&output.stdout).unwrap(), &mut include_dirs);
    }

    build_shim(&include_dirs);
}

