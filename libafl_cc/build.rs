use std::{
    env,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    str,
};

#[cfg(target_vendor = "apple")]
use glob::glob;
use which::which;

/// The max version of `LLVM` we're looking for
#[cfg(not(target_vendor = "apple"))]
const LLVM_VERSION_MAX: u32 = 33;

/// The min version of `LLVM` we're looking for
#[cfg(not(target_vendor = "apple"))]
const LLVM_VERSION_MIN: u32 = 6;

/// Get the extension for a shared object
fn dll_extension<'a>() -> &'a str {
    if let Ok(vendor) = env::var("CARGO_CFG_TARGET_VENDOR") {
        if vendor == "apple" {
            return "dylib";
        }
    }
    let family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap();
    match family.as_str() {
        "windows" => "dll",
        "unix" => "so",
        _ => panic!("Unsupported target family: {family}"),
    }
}

/// Github Actions for `MacOS` seems to have troubles finding `llvm-config`.
/// Hence, we go look for it ourselves.
#[cfg(target_vendor = "apple")]
fn find_llvm_config_brew() -> Result<PathBuf, String> {
    match Command::new("brew").arg("--cellar").output() {
        Ok(output) => {
            let brew_cellar_location = str::from_utf8(&output.stdout).unwrap_or_default().trim();
            if brew_cellar_location.is_empty() {
                return Err("Empty return from brew --cellar".to_string());
            }
            let location_suffix = "*/bin/llvm-config";
            let cellar_glob = vec![
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

fn find_llvm_config() -> Result<String, String> {
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
    };

    #[cfg(not(target_vendor = "apple"))]
    for version in (LLVM_VERSION_MIN..=LLVM_VERSION_MAX).rev() {
        let llvm_config_name: String = format!("llvm-config-{version}");
        if which(&llvm_config_name).is_ok() {
            return Ok(llvm_config_name);
        }
    }

    if which("llvm-config").is_ok() {
        return Ok("llvm-config".to_owned());
    }

    Err("could not find llvm-config".to_owned())
}

fn exec_llvm_config(args: &[&str]) -> String {
    let llvm_config = find_llvm_config().expect("Unexpected error");
    match Command::new(llvm_config).args(args).output() {
        Ok(output) => String::from_utf8(output.stdout)
            .expect("Unexpected llvm-config output")
            .trim()
            .to_string(),
        Err(e) => panic!("Could not execute llvm-config: {e}"),
    }
}

/// Use `xcrun` to get the path to the Xcode SDK tools library path, for linking
fn find_macos_sdk_libs() -> String {
    let sdk_path_out = Command::new("xcrun")
        .arg("--show-sdk-path")
        .output()
        .expect("Failed to execute xcrun. Make sure you have Xcode installed and executed `sudo xcode-select --install`");
    format!(
        "-L{}/usr/lib",
        String::from_utf8(sdk_path_out.stdout).unwrap().trim()
    )
}

fn find_llvm_version() -> Option<i32> {
    let llvm_env_version = env::var("LLVM_VERSION");
    let output = if let Ok(version) = llvm_env_version {
        version
    } else {
        exec_llvm_config(&["--version"])
    };
    if let Some(major) = output.split('.').collect::<Vec<&str>>().first() {
        if let Ok(res) = major.parse::<i32>() {
            return Some(res);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn build_pass(
    bindir_path: &Path,
    out_dir: &Path,
    cxxflags: &Vec<String>,
    ldflags: &Vec<&str>,
    src_dir: &Path,
    src_file: &str,
    additional_srcfiles: Option<&Vec<&str>>,
    optional: bool,
) {
    let dot_offset = src_file.rfind('.').unwrap();
    let src_stub = &src_file[..dot_offset];

    let additionals = if let Some(x) = additional_srcfiles {
        x.iter().map(|f| src_dir.join(f)).collect::<Vec<PathBuf>>()
    } else {
        Vec::new()
    };

    println!("cargo:rerun-if-changed=src/{src_file}");
    let r = if cfg!(unix) {
        let r = Command::new(bindir_path.join("clang++"))
            .arg("-v")
            .args(cxxflags)
            .arg(src_dir.join(src_file))
            .args(additionals)
            .args(ldflags)
            .arg("-o")
            .arg(out_dir.join(format!("{src_stub}.{}", dll_extension())))
            .status();

        Some(r)
    } else if cfg!(windows) {
        let r = Command::new(bindir_path.join("clang-cl.exe"))
            .arg("-v")
            .args(cxxflags)
            .arg(src_dir.join(src_file))
            .args(additionals)
            .arg("/link")
            .args(ldflags)
            .arg(format!(
                "/OUT:{}",
                out_dir
                    .join(format!("{src_stub}.{}", dll_extension()))
                    .display()
            ))
            .status();
        Some(r)
    } else {
        None
    };

    match r {
        Some(r) => match r {
            Ok(s) => {
                if !s.success() {
                    if optional {
                        println!("cargo:warning=Skipping src/{src_file}");
                    } else {
                        panic!("Failed to compile {src_file}");
                    }
                }
            }
            Err(_) => {
                if optional {
                    println!("cargo:warning=Skipping src/{src_file}");
                } else {
                    panic!("Failed to compile {src_file}");
                }
            }
        },
        None => {
            println!("cargo:warning=Skipping src/{src_file}");
        }
    }
}

#[allow(clippy::single_element_loop)]
#[allow(clippy::too_many_lines)]
fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);
    let src_dir = Path::new("src");

    let dest_path = Path::new(&out_dir).join("clang_constants.rs");
    let mut clang_constants_file = File::create(dest_path).expect("Could not create file");

    println!("cargo:rerun-if-env-changed=LLVM_CONFIG");
    println!("cargo:rerun-if-env-changed=LLVM_BINDIR");
    println!("cargo:rerun-if-env-changed=LLVM_CXXFLAGS");
    println!("cargo:rerun-if-env-changed=LLVM_LDFLAGS");
    println!("cargo:rerun-if-env-changed=LLVM_VERSION");
    println!("cargo:rerun-if-env-changed=LIBAFL_EDGES_MAP_SIZE");
    println!("cargo:rerun-if-env-changed=LIBAFL_ACCOUNTING_MAP_SIZE");
    println!("cargo:rerun-if-changed=src/common-llvm.h");
    println!("cargo:rerun-if-changed=build.rs");

    let llvm_bindir = env::var("LLVM_BINDIR");
    let llvm_cxxflags = env::var("LLVM_CXXFLAGS");
    let llvm_ldflags = env::var("LLVM_LDFLAGS");
    let llvm_version = env::var("LLVM_VERSION");

    // test if llvm-config is available and we can compile the passes
    if find_llvm_config().is_err()
        && !(llvm_bindir.is_ok()
            && llvm_cxxflags.is_ok()
            && llvm_ldflags.is_ok()
            && llvm_version.is_ok())
    {
        println!(
            "cargo:warning=Failed to find llvm-config, we will not build LLVM passes. If you need them, set the LLVM_CONFIG environment variable to a recent llvm-config."
        );

        write!(
            clang_constants_file,
            "// These constants are autogenerated by build.rs
/// The path to the `clang` executable
pub const CLANG_PATH: &str = \"clang\";
/// The path to the `clang++` executable
pub const CLANGXX_PATH: &str = \"clang++\";
/// The llvm version used to build llvm passes
pub const LIBAFL_CC_LLVM_VERSION: Option<usize> = None;
    "
        )
        .expect("Could not write file");

        return;
    }

    let llvm_bindir = if let Ok(bindir) = llvm_bindir {
        bindir
    } else {
        exec_llvm_config(&["--bindir"])
    };
    let bindir_path = Path::new(&llvm_bindir);

    let clang;
    let clangcpp;

    if cfg!(windows) {
        clang = bindir_path.join("clang.exe");
        clangcpp = bindir_path.join("clang++.exe");
    } else {
        clang = bindir_path.join("clang");
        clangcpp = bindir_path.join("clang++");
    }

    if !clang.exists() {
        println!("cargo:warning=Failed to find clang frontend.");
        return;
    }

    if !clangcpp.exists() {
        println!("cargo:warning=Failed to find clang++ frontend.");
        return;
    }

    let cxxflags = if let Ok(flags) = llvm_cxxflags {
        flags
    } else {
        exec_llvm_config(&["--cxxflags"])
    };
    let mut cxxflags: Vec<String> = cxxflags.split_whitespace().map(String::from).collect();

    let edges_map_size: usize = option_env!("LIBAFL_EDGES_MAP_SIZE")
        .map_or(Ok(65536), str::parse)
        .expect("Could not parse LIBAFL_EDGES_MAP_SIZE");
    cxxflags.push(format!("-DLIBAFL_EDGES_MAP_SIZE={edges_map_size}"));

    let acc_map_size: usize = option_env!("LIBAFL_ACCOUNTING_MAP_SIZE")
        .map_or(Ok(65536), str::parse)
        .expect("Could not parse LIBAFL_ACCOUNTING_MAP_SIZE");
    cxxflags.push(format!("-DLIBAFL_ACCOUNTING_MAP_SIZE={acc_map_size}"));

    let llvm_version = find_llvm_version();

    if let Some(ver) = llvm_version {
        if ver >= 14 {
            cxxflags.push(String::from("-DUSE_NEW_PM"));
        }
    }

    write!(
        clang_constants_file,
        "// These constants are autogenerated by build.rs

        /// The path to the `clang` executable
        pub const CLANG_PATH: &str = {clang:?};
        /// The path to the `clang++` executable
        pub const CLANGXX_PATH: &str = {clangcpp:?};

        /// The size of the edges map
        pub const EDGES_MAP_SIZE: usize = {edges_map_size};

        /// The size of the accounting maps
        pub const ACCOUNTING_MAP_SIZE: usize = {acc_map_size};

        /// The llvm version used to build llvm passes
        pub const LIBAFL_CC_LLVM_VERSION: Option<usize> = {llvm_version:?};
        ",
    )
    .expect("Could not write file");

    let mut llvm_config_ld = vec![];
    if cfg!(target_vendor = "apple") {
        llvm_config_ld.push("--libs");
    }
    if cfg!(windows) {
        llvm_config_ld.push("--libs");
        llvm_config_ld.push("--system-libs");
    }
    llvm_config_ld.push("--ldflags");

    let ldflags = if let Ok(flags) = llvm_ldflags {
        flags
    } else {
        exec_llvm_config(&llvm_config_ld)
    };
    let mut ldflags: Vec<&str> = ldflags.split_whitespace().collect();

    if cfg!(unix) {
        cxxflags.push(String::from("-shared"));
        cxxflags.push(String::from("-fPIC"));
    }
    if cfg!(windows) {
        cxxflags.push(String::from("-fuse-ld=lld"));
        cxxflags.push(String::from("/LD"));
        /* clang on Windows links against the libcmt.lib runtime
         * however, the distributed binaries are compiled against msvcrt.lib
         * we need to also use msvcrt.lib instead of libcmt.lib when building the optimization passes
         * first, we tell clang-cl (and indirectly link) to ignore libcmt.lib via -nodefaultlib:libcmt
         * second, we pass the /MD flag to clang-cl to use the msvcrt.lib runtime instead when generating the object file
         */
        ldflags.push("-nodefaultlib:libcmt");
        cxxflags.push(String::from("/MD"));
        /* the include directories are not always added correctly when running --cxxflags or --includedir on windows
         * this is somehow related to where/how llvm was compiled (vm, docker container, host)
         * add the option of setting additional flags via the LLVM_CXXFLAGS variable
         */
        if let Some(env_cxxflags) = option_env!("LLVM_CXXFLAGS") {
            cxxflags.append(&mut env_cxxflags.split_whitespace().map(String::from).collect());
        }
    }

    let sdk_path;
    if env::var("CARGO_CFG_TARGET_VENDOR").unwrap().as_str() == "apple" {
        // Needed on macos.
        // Explanation at https://github.com/banach-space/llvm-tutor/blob/787b09ed31ff7f0e7bdd42ae20547d27e2991512/lib/CMakeLists.txt#L59
        ldflags.push("-undefined");
        ldflags.push("dynamic_lookup");

        // In case the system is configured oddly, we may have trouble finding the SDK. Manually add the linker flag, just in case.
        sdk_path = find_macos_sdk_libs();
        ldflags.push(&sdk_path);
    };

    for pass in &[
        "cmplog-routines-pass.cc",
        "afl-coverage-pass.cc",
        "autotokens-pass.cc",
        "coverage-accounting-pass.cc",
        "cmplog-instructions-pass.cc",
        "cmplog-switches-pass.cc",
    ] {
        build_pass(
            bindir_path,
            out_dir,
            &cxxflags,
            &ldflags,
            src_dir,
            pass,
            None,
            false,
        );
    }

    // Optional pass
    for pass in &["dump-cfg-pass.cc"] {
        build_pass(
            bindir_path,
            out_dir,
            &cxxflags,
            &ldflags,
            src_dir,
            pass,
            None,
            true,
        );
    }

    cc::Build::new()
        .file(src_dir.join("no-link-rt.c"))
        .compile("no-link-rt");
}
