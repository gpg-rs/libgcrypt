#[cfg(feature = "shim")]
extern crate gcc;

use std::env;
use std::path::Path;
use std::process::Command;
use std::str;

fn parse_config_output(output: &str, include_dirs: &mut Vec<String>) {
    let parts: Vec<_> = output.split(|c: char| c.is_whitespace()).filter(|p| p.len() > 2)
        .map(|p| (&p[0..2], &p[2..])).collect();

    for &(flag, val) in parts.iter() {
        match flag {
            "-I" => {
                include_dirs.push(val.into());
            },
            "-L" => {
                println!("cargo:rustc-link-search=native={}", val);
            },
            "-F" => {
                println!("cargo:rustc-link-search=framework={}", val);
            },
            "-l" => {
                println!("cargo:rustc-link-lib={}", val);
            },
            _ => {}
        }
    }
}

#[cfg(feature = "shim")]
fn build_shim<P: AsRef<Path>>(include_dirs: &[P]) {
    let mut config = gcc::Config::new();
    for path in include_dirs.iter() {
        config.include(path);
    }
    config.file("shim.c").compile("libgcrypt_shim.a");
}

#[cfg(not(feature = "shim"))]
fn build_shim<P: AsRef<Path>>(_include_dirs: &[P]) {
}

fn fail<S: AsRef<str>>(s: S) -> ! {
    panic!("\n{}\n\nbuild script failed, exiting...", s.as_ref());
}

fn main() {
    let mut command = Command::new(env::var_os("LIBGCRYPT_CONFIG")
                                   .unwrap_or("libgcrypt-config".into()));
    command.arg("--cflags").arg("--libs");
    let output = match command.output() {
        Ok(out) => out,
        Err(err) => {
            fail(format!("failed to run `{:?}`: {}", command, err));
        }
    };

    if !output.status.success() {
        fail(format!("`{:?}` did not exit successfully: {}", command, output.status));
    }

    let mut include_dirs = Vec::new();
    parse_config_output(&str::from_utf8(&output.stdout).unwrap(), &mut include_dirs);
    build_shim(&include_dirs);
}

