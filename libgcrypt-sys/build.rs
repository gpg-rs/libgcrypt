extern crate cc;

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

mod build_helper;

use build_helper::*;

fn main() {
    Project::default().configure(|proj| {
        if let Ok(mut c) = proj.try_env() {
            let _ = c.try_detect_version("gcrypt.h", "GCRYPT_VERSION")?;
            if build_shim(&c).is_ok() {
                return Ok(c);
            }
        }

        if let Some(path) = get_env(proj.prefix.clone() + "CONFIG") {
            return try_config(&proj, path);
        }

        if let r @ Ok(_) = proj.try_build(build) {
            return r;
        }

        try_config(&proj, "libgcrypt-config")
    })
}

#[cfg(feature = "shim")]
fn build_shim(config: &Config) -> Result<()> {
    let mut build = cc::Build::new();
    for path in &config.include_dir {
        build.include(path);
    }
    build
        .flag("-Wno-deprecated-declarations")
        .file("shim.c")
        .try_compile("libgcrypt_shim.a")
        .or(Err(()))
}

#[cfg(not(feature = "shim"))]
fn build_shim(_config: &Config) -> Result<()> {
    Ok(())
}

fn try_config<S: Into<OsString>>(proj: &Project, path: S) -> Result<Config> {
    let path = path.into();
    let mut cmd = path.clone();
    cmd.push(" --version");
    let version = output(Command::new("sh").arg("-c").arg(cmd))?;

    let mut cmd = path;
    cmd.push(" --cflags --libs");
    let mut config = proj.try_config(Command::new("sh").arg("-c").arg(cmd))?;
    config.version = Some(version.trim().into());
    build_shim(&config)?;
    Ok(config)
}

fn build(proj: &Project) -> Result<Config> {
    if proj.target.contains("msvc") {
        return Err(());
    }

    let gpgerror_root = PathBuf::from(env::var_os("DEP_GPG_ERROR_ROOT").ok_or(())?);
    let build = proj.new_build("libgcrypt")?;
    run(Command::new("sh").current_dir(&build.src).arg("autogen.sh"))?;
    let mut cmd = build.configure_cmd()?;
    cmd.arg("--disable-doc");
    cmd.arg({
        let mut s = OsString::from("--with-libgpg-error-prefix=");
        s.push(msys_compatible(&gpgerror_root)?);
        s
    });
    run(cmd)?;
    run(build.make_cmd())?;
    run(build.make_cmd().arg("install"))?;

    let mut config = build.config();
    config.parse_libtool_file(proj.out_dir.join("lib/libgcrypt.la"))?;
    config.try_detect_version("gcrypt.h", "GCRYPT_VERSION")?;
    build_shim(&config)?;
    Ok(config)
}
