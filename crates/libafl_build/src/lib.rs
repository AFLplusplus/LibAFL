#![doc = include_str!("../README.md")]
#![cfg_attr(
    not(test),
    warn(
        missing_debug_implementations,
        missing_docs,
        trivial_casts,
        trivial_numeric_casts,
        unused_extern_crates,
        unused_import_braces,
        unused_qualifications,
        unused_results
    )
)]
#![cfg_attr(
    test,
    deny(
        missing_debug_implementations,
        missing_docs,
        trivial_casts,
        trivial_numeric_casts,
        unused_extern_crates,
        unused_import_braces,
        unused_qualifications,
        unused_must_use,
        unused_results
    )
)]
#![cfg_attr(
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        no_mangle_generic_items,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]

use std::{env, process::Command};

use which::which;

#[cfg(not(target_vendor = "apple"))]
/// The maximum supported LLVM version
pub const LLVM_VERSION_MAX: u32 = 33;

#[cfg(not(target_vendor = "apple"))]
/// The minimum supported LLVM versions
pub const LLVM_VERSION_MIN: u32 = 15;

/// Search for `llvm-config` in the system.
///
/// It checks:
/// 1. `LLVM_CONFIG` environment variable.
/// 2. `llvm-config` in `brew` (MacOS).
/// 3. `llvm-config-VERSION` for versions in `LLVM_VERSION_MIN..=LLVM_VERSION_MAX`.
/// 4. `llvm-config` in PATH.
///
/// If an exact match is not found, it tries to find the newest available version.
pub fn find_llvm_config() -> Result<String, String> {
    if let Ok(var) = env::var("LLVM_CONFIG") {
        return Ok(var);
    }

    // for Github Actions, we check if we find llvm-config in brew.
    #[cfg(target_vendor = "apple")]
    match find_llvm_config_brew() {
        Ok(llvm_dir) => return Ok(llvm_dir.to_str().unwrap().to_string()),
        Err(err) => {
            println!("cargo:warning={err}");
        }
    }

    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    for version in (LLVM_VERSION_MIN..=LLVM_VERSION_MAX).rev() {
        let llvm_config_name: String = format!("/usr/clang/{version}.0/bin/llvm-config");
        if Path::new(&llvm_config_name).exists() {
            return Ok(llvm_config_name);
        }
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "solaris", target_os = "illumos")))]
    {
        // First try to find a version that is >= rustc_llvm_ver if we can determine it,
        // but since this is a generic helper, we just search for all versions.
        // We can prioritize versions if needed.

        for version in (LLVM_VERSION_MIN..=LLVM_VERSION_MAX).rev() {
            let llvm_config_name: String = format!("llvm-config-{version}");
            if which(&llvm_config_name).is_ok() {
                return Ok(llvm_config_name);
            }
        }
    }

    if which("llvm-config").is_ok() {
        return Ok("llvm-config".to_owned());
    }

    Err("could not find llvm-config".to_owned())
}

/// Execute `llvm-config` with the given arguments.
///
/// # Panics
/// Panics if `llvm-config` cannot be found or executed.
pub fn exec_llvm_config(args: &[&str]) -> Result<String, String> {
    let llvm_config = find_llvm_config()?;
    match Command::new(&llvm_config).args(args).output() {
        Ok(output) => {
            if output.status.success() {
                Ok(String::from_utf8(output.stdout)
                    .expect("Unexpected llvm-config output")
                    .trim()
                    .to_string())
            } else {
                Err(format!(
                    "llvm-config failed with error: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))
            }
        }
        Err(e) => Err(format!("Could not execute {llvm_config}: {e}")),
    }
}

/// Find the LLVM version.
///
/// Checks `LLVM_VERSION` environment variable first, then calls `llvm-config --version`.
pub fn find_llvm_version() -> Option<i32> {
    let llvm_env_version = env::var("LLVM_VERSION");
    let output = if let Ok(version) = llvm_env_version {
        version
    } else {
        exec_llvm_config(&["--version"]).ok()?
    };
    if let Some(major) = output.split('.').collect::<Vec<&str>>().first() {
        if let Ok(res) = major.parse::<i32>() {
            return Some(res);
        }
    }
    None
}

/// Find a specific LLVM tool (e.g., `llvm-nm`, `llvm-objcopy`).
///
/// Checks `TOOL_NAME` environment variable (uppercased, hyphens to underscores),
/// then searches for versioned binaries, then the plain binary name.
pub fn find_llvm_tool(tool: &str) -> Result<String, String> {
    if let Ok(var) = env::var(tool.to_uppercase().replace('-', "_")) {
        return Ok(var);
    }

    let tool_name = tool;
    #[cfg(not(any(target_vendor = "apple", target_os = "solaris", target_os = "illumos")))]
    {
        let tool_name_versioned = |version: u32| format!("{tool}-{version}");
        for version in (LLVM_VERSION_MIN..=LLVM_VERSION_MAX).rev() {
            let name = tool_name_versioned(version);
            if which(&name).is_ok() {
                return Ok(name);
            }
        }
    }

    if which(tool_name).is_ok() {
        return Ok(tool_name.to_owned());
    }

    Err(format!("could not find {tool}"))
}

#[cfg(target_vendor = "apple")]
fn find_llvm_config_brew() -> Result<std::path::PathBuf, String> {
    use std::str;

    use glob::glob;

    match Command::new("brew").arg("--prefix").output() {
        Ok(output) => {
            let brew_location = str::from_utf8(&output.stdout).unwrap_or_default().trim();
            if brew_location.is_empty() {
                return Err("Empty return from brew --prefix".to_string());
            }
            let location_suffix = "opt/llvm/bin/llvm-config";
            let prefix_glob = [
                // location for non cellared llvm
                format!("{brew_location}/{location_suffix}"),
            ];
            let glob_results = prefix_glob.iter().flat_map(|location| {
                glob(location).unwrap_or_else(|err| {
                    panic!("Could not read glob path {location} ({err})");
                })
            });
            if let Some(path) = glob_results.last() {
                return Ok(path.unwrap());
            }
        }
        Err(err) => return Err(format!("Could not execute brew --prefix: {err:?}")),
    }
    match Command::new("brew").arg("--cellar").output() {
        Ok(output) => {
            let brew_cellar_location = str::from_utf8(&output.stdout).unwrap_or_default().trim();
            if brew_cellar_location.is_empty() {
                return Err("Empty return from brew --cellar".to_string());
            }
            let location_suffix = "*/bin/llvm-config";
            let cellar_glob = [
                // location for explicitly versioned brew formulae
                format!("{brew_cellar_location}/llvm@*/{location_suffix}"),
                // location for current release brew formulae
                format!("{brew_cellar_location}/llvm/{location_suffix}"),
            ];
            let glob_results = cellar_glob.iter().flat_map(|location| {
                glob(location).unwrap_or_else(|err| {
                    panic!("Could not read glob path {location} ({err})");
                })
            });
            match glob_results.last() {
                Some(path) => Ok(path.unwrap()),
                None => Err(format!(
                    "No llvm-config found in brew cellar with patterns {}",
                    cellar_glob.join(" ")
                )),
            }
        }
        Err(err) => Err(format!("Could not execute brew --cellar: {err:?}")),
    }
}

/// Execute `rustc` with the given arguments.
///
/// # Panics
/// Panics if `rustc` cannot be executed.
pub fn exec_rustc(args: &[&str]) -> String {
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    match Command::new(rustc).args(args).output() {
        Ok(output) => String::from_utf8(output.stdout)
            .expect("Unexpected rustc output")
            .trim()
            .to_string(),
        Err(e) => panic!("Could not execute rustc: {e}"),
    }
}

/// Find the LLVM version used by `rustc`.
pub fn find_rustc_llvm_version() -> Option<i32> {
    let output = exec_rustc(&["--verbose", "--version"]);
    let ver = output.split(':').next_back().unwrap().trim();
    if let Some(major) = ver.split('.').collect::<Vec<&str>>().first() {
        if let Ok(res) = major.parse::<i32>() {
            return Some(res);
        }
    }
    None
}

/// Get the extension for a shared object (dll, so, dylib)
///
/// # Panics
/// Panics if the target family is unsupported (not windows or unix).
pub fn dll_extension<'a>() -> &'a str {
    if let Ok(vendor) = env::var("CARGO_CFG_TARGET_VENDOR") {
        if vendor == "apple" {
            return "dylib";
        }
    }
    let family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_else(|_| "unknown".into());
    match family.as_str() {
        "windows" => "dll",
        "unix" => "so",
        _ => panic!("Unsupported target family: {family}"),
    }
}

/// Use `xcrun` to get the path to the Xcode SDK tools library path, for linking
///
/// # Panics
/// Panics if `xcrun` fails to execute.
pub fn find_macos_sdk_libs() -> String {
    let sdk_path_out = Command::new("xcrun")
        .arg("--show-sdk-path")
        .output()
        .expect("Failed to execute xcrun. Make sure you have Xcode installed and executed `sudo xcode-select --install`");
    format!(
        "-L{}/usr/lib",
        String::from_utf8(sdk_path_out.stdout).unwrap().trim()
    )
}

/// Get the LLVM bindir.
///
/// Checks `LLVM_BINDIR` env var first, then `llvm-config --bindir`.
pub fn llvm_bindir() -> Result<String, String> {
    if let Ok(bindir) = env::var("LLVM_BINDIR") {
        Ok(bindir)
    } else {
        exec_llvm_config(&["--bindir"])
    }
}

/// Get the LLVM cxxflags.
///
/// Checks `LLVM_CXXFLAGS` env var first, then `llvm-config --cxxflags`.
pub fn llvm_cxxflags() -> Result<Vec<String>, String> {
    let cxxflags = if let Ok(flags) = env::var("LLVM_CXXFLAGS") {
        flags
    } else {
        exec_llvm_config(&["--cxxflags"])?
    };
    Ok(cxxflags.split_whitespace().map(String::from).collect())
}

/// Get the LLVM ldflags.
///
/// Checks `LLVM_LDFLAGS` env var first, then `llvm-config --ldflags` (with system libs on Windows/Apple).
pub fn llvm_ldflags() -> Result<Vec<String>, String> {
    if let Ok(flags) = env::var("LLVM_LDFLAGS") {
        return Ok(flags.split_whitespace().map(String::from).collect());
    }

    let mut llvm_config_ld = vec![];
    if cfg!(target_vendor = "apple") {
        llvm_config_ld.push("--libs");
    }
    if cfg!(windows) {
        llvm_config_ld.push("--libs");
        llvm_config_ld.push("--system-libs");
    }
    llvm_config_ld.push("--ldflags");

    let ldflags = exec_llvm_config(&llvm_config_ld)?;
    Ok(ldflags.split_whitespace().map(String::from).collect())
}
