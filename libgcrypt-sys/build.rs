extern crate cc;
use std::{ffi::OsString, process::Command};

mod build_helper;

use build_helper::*;

fn main() -> Result<()> {
    fn configure() -> Result<Config> {
        let proj = Project::default();
        if let r @ Ok(_) = proj.try_env() {
            return r;
        }

        if let Some(path) = get_env(proj.prefix.clone() + "_CONFIG") {
            return try_config(&proj, path);
        }

        try_config(&proj, "libgcrypt-config")
    }
    let mut config = configure()?;
    build_shim(&config)?;
    if config.version.is_none() {
        config.try_detect_version("gcrypt.h", "GCRYPT_VERSION")?;
    }
    config.write_version_macro("gcrypt");
    config.print();
    Ok(())
}

#[cfg(feature = "shim")]
fn build_shim(config: &Config) -> Result<()> {
    let mut build = cc::Build::new();
    for path in &config.include_dir {
        if path.exists() {
            build.include(path);
        }
    }
    build
        .file("shim.c")
        .flag_if_supported("-Wno-deprecated-declarations")
        .try_compile("libgcrypt_shim.a")
        .warn_err("unable to build shim")
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
    proj.try_config(Command::new("sh").arg("-c").arg(cmd))
        .map(|mut cfg| {
            cfg.version = Some(version.trim().into());
            cfg
        })
}
