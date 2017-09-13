extern crate semver;
extern crate gcc;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::result;
use std::str;

use semver::Version;

type Result<T> = result::Result<T, ()>;

const INCLUDED_VERSION: &str = "1.8.1";

fn main() {
    if let Err(_) = configure() {
        process::exit(1);
    }
}

fn configure() -> Result<()> {
    println!("cargo:rerun-if-env-changed=LIBGCRYPT_LIB_DIR");
    let path = env::var_os("LIBGCRYPT_LIB_DIR");
    println!("cargo:rerun-if-env-changed=LIBGCRYPT_LIBS");
    let libs = env::var_os("LIBGCRYPT_LIBS");
    println!("cargo:rerun-if-env-changed=LIBGCRYPT_INCLUDE_DIR");
    let include = env::var_os("LIBGCRYPT_INCLUDE_DIR");
    if path.is_some() || libs.is_some() || include.is_some() {
        println!("cargo:rerun-if-env-changed=LIBGCRYPT_STATIC");
        let mode = match env::var_os("LIBGCRYPT_STATIC") {
            Some(_) => "static",
            _ => "dylib",
        };

        let includes = include.iter().flat_map(env::split_paths).collect::<Vec<_>>();
        let version = detect_version(&includes)?;
        build_shim(&includes)?;

        print_version(version);
        for path in path.iter().flat_map(env::split_paths) {
            println!("cargo:rustc-link-search=native={}", path.display());
        }
        for lib in env::split_paths(libs.as_ref().map(|s| &**s).unwrap_or("gcrypt".as_ref())) {
            println!("cargo:rustc-link-lib={0}={1}", mode, lib.display());
        }
        return Ok(());
    }

    println!("cargo:rerun-if-env-changed=LIBGCRYPT_CONFIG");
    if let Some(path) = env::var_os("LIBGCRYPT_CONFIG") {
        return try_config(path);
    }

    if !Path::new("libgcrypt/autogen.sh").exists() {
        let _ = run(Command::new("git").args(&["submodule", "update", "--init"]));
    }

    try_build().or_else(|_| try_config("libgcrypt-config"))
}

fn detect_version<P: AsRef<Path>>(includes_dirs: &[P]) -> Result<Version> {
    use std::fs::File;
    use std::io::{self, BufRead, BufReader};

    eprintln!("detecting installed version of libgcrypt");
    let defaults = &["/usr/include".as_ref(), "/usr/local/include".as_ref()];
    for dir in includes_dirs.iter().map(|x| x.as_ref()).chain(defaults.iter().cloned()) {
        let name = dir.join("gcrypt.h");
        let mut file = match File::open(name.clone()) {
            Ok(f) => BufReader::new(f),
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    eprintln!("skipping not existent file: {}", name.display());
                } else {
                    eprintln!("unable to inspect file `{}`: {}", name.display(), e);
                }
                continue;
            }
        };
        let mut line = String::new();
        loop {
            line.clear();
            if file.read_line(&mut line).unwrap() == 0 {
                break;
            }

            if let Some(p) = line.find("GCRYPT_VERSION ") {
                if let Some(v) = (&line[p..]).split('\"').nth(1).and_then(|s| Version::parse(s).ok()) {
                    eprintln!("found version: {}", v);
                    return Ok(v);
                }
                break;
            }
        }
    }
    Err(())
}

fn print_version(v: Version) {
    println!("cargo:version={}", v);
    println!("cargo:version_major={}", v.major);
    println!("cargo:version_minor={}", v.minor);
    println!("cargo:version_patch={}", v.patch);
}

#[cfg(feature = "shim")]
fn build_shim<P: AsRef<Path>>(include_dirs: &[P]) -> Result<()> {
    let mut config = gcc::Build::new();
    for path in include_dirs {
        config.include(path);
    }
    config
        .flag("-Wno-deprecated-declarations")
        .file("shim.c")
        .try_compile("libgcrypt_shim.a").or(Err(()))
}

#[cfg(not(feature = "shim"))]
fn build_shim<P: AsRef<Path>>(_include_dirs: &[P]) -> Result<()> { Ok(()) }

fn parse_config_output(output: &str, include_dirs: &mut Vec<OsString>) {
    let parts = output
        .split(|c: char| c.is_whitespace())
        .filter_map(|p| if p.len() > 2 {
            Some(p.split_at(2))
        } else {
            None
        });

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

fn try_config<S: Into<OsString>>(path: S) -> Result<()> {
    let path = path.into();
    let mut cmd = path.clone();
    cmd.push(" --version");
    let version = Version::parse(&output(Command::new("sh").arg("-c").arg(cmd))?).or(Err(()))?;

    let mut cmd = path;
    cmd.push(" --cflags --libs");
    let output = output(Command::new("sh").arg("-c").arg(cmd))?;

    let mut includes = Vec::new();
    parse_config_output(&output, &mut includes);
    build_shim(&includes)?;
    print_version(version);
    Ok(())
}


fn try_build() -> Result<()> {
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    let src = PathBuf::from(env::current_dir().unwrap()).join("libgcrypt");
    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let build = dst.join("build");
    let gpgerror_root = PathBuf::from(env::var("DEP_GPG_ERROR_ROOT").unwrap());
    let compiler = gcc::Build::new().get_compiler();
    let cflags = compiler.args().iter().fold(OsString::new(), |mut c, a| {
        c.push(a);
        c.push(" ");
        c
    });

    if target.contains("msvc") {
        return Err(());
    }

    fs::create_dir_all(&build).map_err(|e| eprintln!("unable to create build directory: {}", e))?;

    run(Command::new("sh").current_dir(&src).arg("autogen.sh"))?;
    run(Command::new("sh")
        .current_dir(&build)
        .env("CC", compiler.path())
        .env("CFLAGS", &cflags)
        .arg(msys_compatible(src.join("configure"))?)
        .args(&[
              "--build",
              &gnu_target(&host),
              "--host",
              &gnu_target(&target),
              "--enable-static",
              "--disable-shared",
              "--disable-doc",
        ])
        .arg({
            let mut s = OsString::from("--with-libgpg-error-prefix=");
            s.push(msys_compatible(&gpgerror_root)?);
            s
        })
        .arg({
            let mut s = OsString::from("--prefix=");
            s.push(msys_compatible(&dst)?);
            s
        }))?;
    run(make().current_dir(&build))?;
    run(make().current_dir(&build).arg("install"))?;

    build_shim(&[gpgerror_root.join("include"), dst.join("include")])?;

    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=gcrypt");
    println!("cargo:root={}", dst.display());
    print_version(Version::parse(INCLUDED_VERSION).unwrap());
    Ok(())
}


fn make() -> Command {
    let name = if cfg!(any(target_os = "freebsd", target_os = "dragonfly")) {
        "gmake"
    } else {
        "make"
    };
    let mut cmd = Command::new(name);
    cmd.env_remove("DESTDIR");
    if cfg!(windows) {
        cmd.env_remove("MAKEFLAGS").env_remove("MFLAGS");
    }
    cmd
}

fn msys_compatible<P: AsRef<OsStr>>(path: P) -> Result<OsString> {
    use std::ascii::AsciiExt;

    if !cfg!(windows) || Path::new(path.as_ref()).is_relative() {
        return Ok(path.as_ref().to_owned());
    }

    let mut path = path.as_ref()
        .to_str()
        .ok_or_else(|| eprintln!("path is not valid utf-8"))?
        .to_owned();
    if let Some(b'a'...b'z') = path.as_bytes().first().map(u8::to_ascii_lowercase) {
        if path.split_at(1).1.starts_with(":\\") {
            (&mut path[..1]).make_ascii_lowercase();
            path.remove(1);
            path.insert(0, '/');
        }
    }
    Ok(path.replace("\\", "/").into())
}

fn gnu_target(target: &str) -> String {
    match target {
        "i686-pc-windows-gnu" => "i686-w64-mingw32".to_string(),
        "x86_64-pc-windows-gnu" => "x86_64-w64-mingw32".to_string(),
        s => s.to_string(),
    }
}

fn run(cmd: &mut Command) -> Result<String> {
    eprintln!("running: {:?}", cmd);
    match cmd.stdin(Stdio::null())
        .spawn()
        .and_then(|c| c.wait_with_output())
    {
        Ok(output) => if output.status.success() {
            String::from_utf8(output.stdout).or(Err(()))
        } else {
            eprintln!(
                "command did not execute successfully, got: {}",
                output.status
            );
            Err(())
        },
        Err(e) => {
            eprintln!("failed to execute command: {}", e);
            Err(())
        }
    }
}

fn output(cmd: &mut Command) -> Result<String> {
    run(cmd.stdout(Stdio::piped()))
}
