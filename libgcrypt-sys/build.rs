#[macro_use]
extern crate cfg_if;
extern crate gcc;

use std::cmp::Ordering;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::iter;
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command, Stdio};
use std::str;

cfg_if! {
    if #[cfg(feature = "v1_8_0")] {
        const TARGET_VERSION: &'static str = "1.8.0";
    } else if #[cfg(feature = "v1_7_0")] {
        const TARGET_VERSION: &'static str = "1.7.0";
    } else if #[cfg(feature = "v1_6_0")] {
        const TARGET_VERSION: &'static str = "1.6.0";
    } else {
        const TARGET_VERSION: &'static str = "1.5.0";
    }
}

fn main() {
    let path = env::var_os("LIBGCRYPT_LIB_PATH");
    let libs = env::var_os("LIBGCRYPT_LIBS");
    let include = env::var_os("LIBGCRYPT_INCLUDE_DIR");
    if path.is_some() || libs.is_some() || include.is_some() {
        let mode = match env::var_os("LIBGCRYPT_STATIC") {
            Some(_) => "static",
            _ => "dylib",
        };

        for path in path.iter().flat_map(env::split_paths) {
            println!("cargo:rustc-link-search=native={}", path.display());
        }

        let mut includes = Vec::new();
        for include in include.iter().flat_map(env::split_paths) {
            includes.push(include)
        }
        build_shim(&includes);

        match libs {
            Some(libs) => for lib in env::split_paths(&libs) {
                println!("cargo:rustc-link-lib={0}={1}", mode, lib.display());
            },
            None => {
                println!("cargo:rustc-link-lib={0}={1}", mode, "gcrypt");
            }
        }
        return;
    } else if let Some(path) = env::var_os("LIBGCRYPT_CONFIG") {
        if !try_config(path) {
            process::exit(1);
        }
        return;
    }

    if !Path::new("libgcrypt/autogen.sh").exists() {
        run(Command::new("git").args(&["submodule", "update", "--init"]));
    }

    if try_build() || try_config("libgcrypt-config") {
        return;
    }
    process::exit(1);
}

fn try_config<S: AsRef<OsStr>>(path: S) -> bool {
    let path = path.as_ref();

    let mut cmd = path.to_owned();
    cmd.push(" --version");
    if let Some(output) = output(Command::new("sh").arg("-c").arg(cmd)) {
        test_version(&output);
    } else {
        return false;
    }

    let mut cmd = path.to_owned();
    cmd.push(" --prefix");
    if let Some(output) = output(Command::new("sh").arg("-c").arg(cmd)) {
        println!("cargo:root={}", output);
    }

    let mut cmd = path.to_owned();
    cmd.push(" --cflags --libs");
    if let Some(output) = output(Command::new("sh").arg("-c").arg(cmd)) {
        let mut includes = Vec::new();
        parse_config_output(&output, &mut includes);
        build_shim(&includes);
        return true;
    }
    false
}

fn try_build() -> bool {
    let src = PathBuf::from(env::current_dir().unwrap()).join("libgcrypt");
    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let build = dst.clone().join("build");
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    let gpgerror_root = env::var("DEP_GPG_ERROR_ROOT").unwrap();
    let compiler = gcc::Config::new().get_compiler();
    let cflags = compiler.args().iter().fold(OsString::new(), |mut c, a| {
        c.push(a);
        c.push(" ");
        c
    });

    let _ = fs::create_dir_all(&build);

    if !run(Command::new("sh").current_dir(&src).arg("autogen.sh")) {
        return false;
    }
    if !run(
        Command::new("sh")
            .current_dir(&build)
            .env("CC", compiler.path())
            .env("CFLAGS", &cflags)
            .arg(msys_compatible(src.join("configure")))
            .args(&[
                "--build",
                &gnu_target(&host),
                "--host",
                &gnu_target(&target),
                "--enable-static",
                "--disable-shared",
                "--disable-doc",
                &format!(
                    "--with-libgpg-error-prefix={}",
                    &msys_compatible(&gpgerror_root)
                ),
                &format!("--prefix={}", msys_compatible(&dst)),
            ]),
    ) {
        return false;
    }
    if !run(
        Command::new("make")
            .current_dir(&build)
            .arg("-j")
            .arg(env::var("NUM_JOBS").unwrap()),
    ) {
        return false;
    }
    if !run(Command::new("make").current_dir(&build).arg("install")) {
        return false;
    }

    build_shim(&[
        PathBuf::from(gpgerror_root).join("include"),
        PathBuf::from(dst.clone()).join("include"),
    ]);

    println!(
        "cargo:rustc-link-search=native={}",
        dst.clone().join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=gcrypt");
    println!("cargo:root={}", dst.display());
    true
}

#[cfg(feature = "shim")]
fn build_shim<P: AsRef<Path>>(include_dirs: &[P]) {
    let mut config = gcc::Config::new();
    for path in include_dirs.iter() {
        config.include(path);
    }
    config
        .flag("-Wno-deprecated-declarations")
        .file("shim.c")
        .compile("libgcrypt_shim.a");
}

#[cfg(not(feature = "shim"))]
fn build_shim<P: AsRef<Path>>(_include_dirs: &[P]) {}

fn test_version(version: &str) {
    let version = version.trim();
    for (x, y) in TARGET_VERSION
        .split('.')
        .zip(version.split('.').chain(iter::repeat("0")))
    {
        let (x, y): (u8, u8) = (x.parse().unwrap(), y.parse().unwrap());
        match x.cmp(&y) {
            Ordering::Less => break,
            Ordering::Greater => panic!(
                "gcrypt version `{}` is less than requested `{}`",
                version,
                TARGET_VERSION
            ),
            _ => (),
        }
    }
}

fn parse_config_output(output: &str, include_dirs: &mut Vec<OsString>) {
    let parts = output.split(|c: char| c.is_whitespace()).filter_map(
        |p| if p.len() > 2 {
            Some(p.split_at(2))
        } else {
            None
        },
    );

    for (flag, val) in parts {
        match flag {
            "-I" => include_dirs.push(val.into()),
            "-L" => {
                println!("cargo:rustc-link-search=native={}", val);
            }
            "-F" => {
                println!("cargo:rustc-link-search=framework={}", val);
            }
            "-l" => {
                println!("cargo:rustc-link-lib={}", val);
            }
            _ => (),
        }
    }
}

fn spawn(cmd: &mut Command) -> Option<Child> {
    println!("running: {:?}", cmd);
    match cmd.stdin(Stdio::null()).spawn() {
        Ok(child) => Some(child),
        Err(e) => {
            println!("failed to execute command: {:?}\nerror: {}", cmd, e);
            None
        }
    }
}

fn run(cmd: &mut Command) -> bool {
    if let Some(mut child) = spawn(cmd) {
        match child.wait() {
            Ok(status) => if !status.success() {
                println!(
                    "command did not execute successfully: {:?}\n\
                     expected success, got: {}",
                    cmd,
                    status
                );
            } else {
                return true;
            },
            Err(e) => {
                println!("failed to execute command: {:?}\nerror: {}", cmd, e);
            }
        }
    }
    false
}

fn output(cmd: &mut Command) -> Option<String> {
    if let Some(child) = spawn(cmd.stdout(Stdio::piped())) {
        match child.wait_with_output() {
            Ok(output) => if !output.status.success() {
                println!(
                    "command did not execute successfully: {:?}\n\
                     expected success, got: {}",
                    cmd,
                    output.status
                );
            } else {
                return String::from_utf8(output.stdout).ok();
            },
            Err(e) => {
                println!("failed to execute command: {:?}\nerror: {}", cmd, e);
            }
        }
    }
    None
}

fn msys_compatible<P: AsRef<Path>>(path: P) -> String {
    use std::ascii::AsciiExt;

    let mut path = path.as_ref().to_string_lossy().into_owned();
    if !cfg!(windows) || Path::new(&path).is_relative() {
        return path;
    }

    if let Some(b'a'...b'z') = path.as_bytes().first().map(u8::to_ascii_lowercase) {
        if path.split_at(1).1.starts_with(":\\") {
            (&mut path[..1]).make_ascii_lowercase();
            path.remove(1);
            path.insert(0, '/');
        }
    }
    path.replace("\\", "/")
}

fn gnu_target(target: &str) -> &str {
    match target {
        "i686-pc-windows-gnu" => "i686-w64-mingw32",
        "x86_64-pc-windows-gnu" => "x86_64-w64-mingw32",
        s => s,
    }
}
