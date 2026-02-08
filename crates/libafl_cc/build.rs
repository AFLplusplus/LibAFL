use core::str;
#[cfg(any(
    target_vendor = "apple",
    feature = "function-logging",
    feature = "cmplog-routines",
    feature = "autotokens",
    feature = "coverage-accounting",
    feature = "cmplog-instructions",
    feature = "ctx",
    feature = "dump-cfg",
))]
use std::path::PathBuf;
#[cfg(any(
    feature = "function-logging",
    feature = "cmplog-routines",
    feature = "autotokens",
    feature = "coverage-accounting",
    feature = "cmplog-instructions",
    feature = "ctx",
    feature = "dump-cfg",
))]
use std::process::Command;
use std::{env, fs::File, io::Write, path::Path};

#[cfg(any(
    feature = "function-logging",
    feature = "cmplog-routines",
    feature = "autotokens",
    feature = "coverage-accounting",
    feature = "cmplog-instructions",
    feature = "ctx",
    feature = "dump-cfg",
))]
#[expect(clippy::too_many_arguments)]
fn build_pass(
    bindir_path: &Path,
    out_dir: &Path,
    cxxflags: &Vec<String>,
    ldflags: &Vec<&str>,
    src_dir: &Path,
    src_file: &str,
    additional_srcfiles: Option<&Vec<&str>>,
    required: bool,
) {
    let dot_offset = src_file.rfind('.').unwrap();
    let src_stub = &src_file[..dot_offset];

    let additionals = if let Some(x) = additional_srcfiles {
        x.iter().map(|f| src_dir.join(f)).collect::<Vec<PathBuf>>()
    } else {
        Vec::new()
    };

    println!("cargo:rerun-if-changed=src/{src_file}");
    let command_result = if cfg!(unix) {
        let r = Command::new(bindir_path.join("clang++"))
            .arg("-v")
            .arg(format!("--target={}", env::var("HOST").unwrap()))
            .args(cxxflags)
            .arg(src_dir.join(src_file))
            .args(additionals)
            .args(ldflags)
            .arg("-o")
            .arg(out_dir.join(format!("{src_stub}.{}", libafl_build::dll_extension())))
            .status();

        Some(r)
    } else if cfg!(windows) {
        let r = Command::new(bindir_path.join("clang-cl.exe"))
            .arg("-v")
            .arg(format!("--target={}", env::var("HOST").unwrap()))
            .args(cxxflags)
            .arg(src_dir.join(src_file))
            .args(additionals)
            .arg("/link")
            .args(ldflags)
            .arg(format!(
                "/OUT:{}",
                out_dir
                    .join(format!("{src_stub}.{}", libafl_build::dll_extension()))
                    .display()
            ))
            .status();
        Some(r)
    } else {
        None
    };

    match command_result {
        Some(res) => match res {
            Ok(s) => {
                if !s.success() {
                    if required {
                        panic!(
                            "Failed to compile required compiler pass src/{src_file} - Exit status: {s}"
                        );
                    } else {
                        println!(
                            "cargo:warning=Skipping non-required compiler pass src/{src_file} - Reason: Exit status {s}. You can ignore this error unless you want this compiler pass."
                        );
                    }
                }
            }
            Err(err) => {
                if required {
                    panic!(
                        "Failed to compile required compiler pass src/{src_file} - Exit status: {err}"
                    );
                } else {
                    println!(
                        "cargo:warning=Skipping non-required compiler pass src/{src_file} - Reason: Exit status {err}. You can ignore this error unless you want this compiler pass."
                    );
                }
            }
        },
        None => {
            println!(
                "cargo:warning=Skipping compiler pass src/{src_file} - Only supported on Windows or *nix."
            );
        }
    }
}

#[expect(clippy::too_many_lines)]
fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);
    let src_dir = Path::new("src");

    let dest_path = Path::new(&out_dir).join("clang_constants.rs");
    let mut clang_constants_file = File::create(dest_path).expect("Could not create file");

    println!("cargo:rerun-if-env-changed=LLVM_CONFIG");
    println!("cargo:rerun-if-env-changed=LLVM_BINDIR");
    println!("cargo:rerun-if-env-changed=LLVM_AR_PATH");
    println!("cargo:rerun-if-env-changed=LLVM_CXXFLAGS");
    println!("cargo:rerun-if-env-changed=LLVM_LDFLAGS");
    println!("cargo:rerun-if-env-changed=LLVM_VERSION");
    println!("cargo:rerun-if-env-changed=LIBAFL_EDGES_MAP_DEFAULT_SIZE");
    println!("cargo:rerun-if-env-changed=LIBAFL_ACCOUNTING_MAP_SIZE");
    println!("cargo:rerun-if-changed=src/common-llvm.h");
    println!("cargo:rerun-if-changed=build.rs");

    let llvm_version = env::var("LLVM_VERSION");

    // test if llvm-config is available and we can compile the passes
    if libafl_build::find_llvm_config().is_err()
        && !(env::var("LLVM_BINDIR").is_ok()
            && env::var("LLVM_CXXFLAGS").is_ok()
            && env::var("LLVM_LDFLAGS").is_ok()
            && llvm_version.is_ok())
    {
        println!(
            "cargo:warning=Failed to find llvm-config, we will not build LLVM passes. If you need them, set the LLVM_CONFIG environment variable to a recent llvm-config, else just ignore this message."
        );

        write!(
            clang_constants_file,
            "// These constants are autogenerated by build.rs
/// The path to the `clang` executable
pub const CLANG_PATH: &str = \"clang\";
/// The path to the `clang++` executable
pub const CLANGXX_PATH: &str = \"clang++\";
/// The path to the `llvm-ar` executable
pub const LLVM_AR_PATH: &str = \"llvm-ar\";
/// The llvm version used to build llvm passes
pub const LIBAFL_CC_LLVM_VERSION: Option<usize> = None;
    "
        )
        .expect("Could not write file");

        return;
    }

    let llvm_bindir = libafl_build::llvm_bindir().expect("Could not find LLVM bindir");
    let llvm_ar_path = env::var("LLVM_AR_PATH");
    let llvm_cxxflags = libafl_build::llvm_cxxflags().expect("Could not find LLVM cxxflags");
    let llvm_ldflags = libafl_build::llvm_ldflags().expect("Could not find LLVM ldflags");

    let bindir_path = Path::new(&llvm_bindir);
    let llvm_ar_path = if let Ok(ar_path) = llvm_ar_path {
        ar_path
    } else {
        libafl_build::exec_llvm_config(&["--bindir"])
            .expect("Could not execute llvm-config --bindir")
    };

    let clang;
    let clangcpp;
    let llvm_ar;

    if cfg!(windows) {
        clang = bindir_path.join("clang.exe");
        clangcpp = bindir_path.join("clang++.exe");
        llvm_ar = Path::new(&llvm_ar_path).join("llvm-ar.exe");
    } else {
        clang = bindir_path.join("clang");
        clangcpp = bindir_path.join("clang++");
        llvm_ar = Path::new(&llvm_ar_path).join("llvm-ar");
    }

    let mut found = true;

    if !clang.exists() {
        println!("cargo:warning=Failed to find binary: clang.");
        found = false;
    }

    if !clangcpp.exists() {
        println!("cargo:warning=Failed to find binary: clang++.");
        found = false;
    }

    if !llvm_ar.exists() {
        println!("cargo:warning=Failed to find binary: llvm-ar.");
        found = false;
    }

    assert!(
        found,
        "\n\tAt least one of the LLVM dependencies could not be found.\n\tThe following search directory was considered: {}\n",
        bindir_path.display()
    );

    let mut cxxflags = llvm_cxxflags;

    let edge_map_default_size: usize = option_env!("LIBAFL_EDGES_MAP_DEFAULT_SIZE")
        .map_or(Ok(65_536), str::parse)
        .expect("Could not parse LIBAFL_EDGES_MAP_DEFAULT_SIZE");
    let edge_map_allocated_size: usize = option_env!("LIBAFL_EDGES_MAP_ALLOCATED_SIZE")
        .map_or(Ok(2_621_440), str::parse)
        .expect("Could not parse LIBAFL_EDGES_MAP_DEFAULT_SIZE");
    cxxflags.push(format!("-DEDGES_MAP_DEFAULT_SIZE={edge_map_default_size}"));

    let acc_map_size: usize = option_env!("LIBAFL_ACCOUNTING_MAP_SIZE")
        .map_or(Ok(65_536), str::parse)
        .expect("Could not parse LIBAFL_ACCOUNTING_MAP_SIZE");
    cxxflags.push(format!("-DACCOUNTING_MAP_SIZE={acc_map_size}"));

    let llvm_version = libafl_build::find_llvm_version();

    // We want the paths quoted, and debug formatting does that - allow debug formatting.
    #[allow(unknown_lints)] // not on stable yet
    #[allow(clippy::unnecessary_debug_formatting)]
    write!(
        clang_constants_file,
        "// These constants are autogenerated by build.rs

        /// The path to the `clang` executable
        pub const CLANG_PATH: &str = {clang:?};
        /// The path to the `clang++` executable
        pub const CLANGXX_PATH: &str = {clangcpp:?};
        /// The path to the `llvm-ar` executable
        pub const LLVM_AR_PATH: &str = {llvm_ar:?};

        /// The default size of the edges map the fuzzer uses
        pub const EDGES_MAP_DEFAULT_SIZE: usize = {edge_map_default_size};
        /// The real allocated size of the edges map
        pub const EDGES_MAP_ALLOCATED_SIZE: usize = {edge_map_allocated_size};

        /// The size of the accounting maps
        pub const ACCOUNTING_MAP_SIZE: usize = {acc_map_size};

        /// The llvm version used to build llvm passes
        pub const LIBAFL_CC_LLVM_VERSION: Option<usize> = {llvm_version:?};
        ",
    )
    .expect("Could not write file");

    let mut ldflags: Vec<&str> = llvm_ldflags.iter().map(String::as_str).collect();

    if cfg!(unix) {
        cxxflags.push(String::from("-shared"));
        cxxflags.push(String::from("-fPIC"));
        cxxflags.push(String::from("-std=c++17")); // std::nullopt_t requires this
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
        sdk_path = libafl_build::find_macos_sdk_libs();
        ldflags.push(&sdk_path);
    }

    #[cfg(feature = "function-logging")]
    build_pass(
        bindir_path,
        out_dir,
        &cxxflags,
        &ldflags,
        src_dir,
        "function-logging.cc",
        None,
        true,
    );

    #[cfg(feature = "cmplog-routines")]
    build_pass(
        bindir_path,
        out_dir,
        &cxxflags,
        &ldflags,
        src_dir,
        "cmplog-routines-pass.cc",
        None,
        true,
    );

    #[cfg(feature = "autotokens")]
    build_pass(
        bindir_path,
        out_dir,
        &cxxflags,
        &ldflags,
        src_dir,
        "autotokens-pass.cc",
        None,
        true,
    );

    #[cfg(feature = "coverage-accounting")]
    build_pass(
        bindir_path,
        out_dir,
        &cxxflags,
        &ldflags,
        src_dir,
        "coverage-accounting-pass.cc",
        None,
        true,
    );

    #[cfg(feature = "cmplog-instructions")]
    build_pass(
        bindir_path,
        out_dir,
        &cxxflags,
        &ldflags,
        src_dir,
        "cmplog-instructions-pass.cc",
        None,
        true,
    );

    #[cfg(feature = "ctx")]
    build_pass(
        bindir_path,
        out_dir,
        &cxxflags,
        &ldflags,
        src_dir,
        "ctx-pass.cc",
        None,
        true,
    );

    #[cfg(feature = "dump-cfg")]
    build_pass(
        bindir_path,
        out_dir,
        &cxxflags,
        &ldflags,
        src_dir,
        "dump-cfg-pass.cc",
        None,
        false,
    );

    cc::Build::new()
        .file(src_dir.join("no-link-rt.c"))
        .compile("no-link-rt");
}
