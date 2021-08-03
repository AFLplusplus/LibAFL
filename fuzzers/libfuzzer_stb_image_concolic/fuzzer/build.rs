// build.rs

use std::env;
use std::io::stdout;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::process::Command;

fn main() {
    let out_path = PathBuf::from(&env::var_os("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=harness.c");

    // Enforce clang for its -fsanitize-coverage support.
    std::env::set_var("CC", "clang");
    std::env::set_var("CXX", "clang++");

    cc::Build::new()
        // Use sanitizer coverage to track the edges in the PUT
        .flag("-fsanitize-coverage=trace-pc-guard,trace-cmp")
        // Take advantage of LTO (needs lld-link set in your cargo config)
        //.flag("-flto=thin")
        .flag("-Wno-sign-compare")
        .file("./harness.c")
        .compile("harness");

    println!(
        "cargo:rustc-link-search=native={}",
        &out_path.to_string_lossy()
    );

    let symcc_dir = clone_and_build_symcc(&out_path);

    let runtime_dir = std::env::current_dir()
        .unwrap()
        .join("..")
        .join("runtime")
        .join("target")
        .join(std::env::var("PROFILE").unwrap());

    if !runtime_dir.join("libSymRuntime.so").exists() {
        println!("cargo:warning=Runtime not found. Build it first.");
        exit(1);
    }

    // SymCC.
    std::env::set_var("CC", symcc_dir.join("symcc"));
    std::env::set_var("CXX", symcc_dir.join("sym++"));
    std::env::set_var("SYMCC_RUNTIME_DIR", runtime_dir);

    let output = cc::Build::new()
        .flag("-Wno-sign-compare")
        .cargo_metadata(false)
        .get_compiler()
        .to_command()
        .arg("./harness_symcc.c")
        .args(["-o", "target_symcc.out"])
        .arg("-lm")
        .output()
        .expect("failed to execute symcc");
    if !output.status.success() {
        println!("cargo:warning=Building the target with SymCC failed");
        let mut stdout = stdout();
        stdout
            .write_all(&output.stderr)
            .expect("failed to write cc error message to stdout");
        exit(1);
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=harness.c");
    println!("cargo:rerun-if-changed=harness_symcc.c");
}

const SYMCC_REPO_URL: &str = "https://github.com/AFLplusplus/symcc.git";
const SYMCC_REPO_COMMIT: &str = "45cde0269ae22aef4cca2e1fb98c3b24f7bb2984";

fn clone_and_build_symcc(out_path: &Path) -> PathBuf {
    let repo_dir = out_path.join("libafl_symcc_src");
    if repo_dir.exists() {
    } else {
        let mut cmd = Command::new("git");
        cmd.arg("clone").arg(SYMCC_REPO_URL).arg(&repo_dir);
        let output = cmd.output().expect("failed to execute git clone");
        if output.status.success() {
            let mut cmd = Command::new("git");
            cmd.arg("checkout")
                .arg(SYMCC_REPO_COMMIT)
                .current_dir(&repo_dir);
            let output = cmd.output().expect("failed to execute git checkout");
            if output.status.success() {
            } else {
                println!("failed to checkout symcc git repository commit:");
                let mut stdout = stdout();
                stdout
                    .write_all(&output.stderr)
                    .expect("failed to write git error message to stdout");
                exit(1)
            }
        } else {
            println!("failed to clone symcc git repository:");
            let mut stdout = stdout();
            stdout
                .write_all(&output.stderr)
                .expect("failed to write git error message to stdout");
            exit(1)
        }
    }

    use cmake::Config;

    Config::new(repo_dir)
        .define("Z3_TRUST_SYSTEM_VERSION", "ON")
        .no_build_target(true)
        .build()
        .join("build")
}
