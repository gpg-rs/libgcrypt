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

        if let r @ Ok(_) = try_registry(&proj) {
            return r;
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

#[cfg(not(windows))]
fn try_registry(_: &Project) -> Result<Config> {
    Err(())
}

#[cfg(windows)]
fn try_registry(proj: &Project) -> Result<Config> {
    use std::{fs, path::PathBuf};
    use winreg::{enums::*, RegKey};

    if !proj.target.contains("windows") {
        eprintln!("cross compiling. disabling registry detection.");
        return Err(());
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let root = PathBuf::from(
        hklm.open_subkey("SOFTWARE\\GnuPG")
            .and_then(|k| k.get_value::<String, _>("Install Directory"))
            .warn_err("unable to retrieve install location")?,
    );
    if root.join("lib/libgcrypt.imp").exists() {
        fs::copy(
            root.join("lib/libgcrypt.imp"),
            proj.out_dir.join("libgcrypt.a"),
        )
        .warn_err("unable to rename library")?;
    }

    let mut config = Config::default();
    config.include_dir.insert(root.join("include"));
    config.lib_dir.insert(proj.out_dir.clone());
    config.libs.insert(proj.links.clone().into());
    config.prefix = Some(root);
    Ok(config)
}
