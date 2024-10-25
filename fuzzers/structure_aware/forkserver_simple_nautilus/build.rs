use std::{
    env,
    path::Path,
    process::{exit, Command},
};

const AFL_URL: &str = "https://github.com/AFLplusplus/AFLplusplus";

fn main() {
    if cfg!(windows) {
        println!("cargo:warning=No support for windows yet.");
        exit(0);
    }

    env::remove_var("DEBUG");
    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();

    let afl = format!("{}/AFLplusplus", &cwd);
    let afl_cc = format!("{}/AFLplusplus/afl-cc", &cwd);

    let afl_path = Path::new(&afl);
    let afl_cc_path = Path::new(&afl_cc);

    if !afl_path.is_dir() {
        println!("cargo:warning=AFL++ not found, downloading...");
        Command::new("git")
            .arg("clone")
            .arg(AFL_URL)
            .status()
            .unwrap();
    }

    if !afl_cc_path.is_file() {
        let mut afl_cc_make = Command::new("make");
        afl_cc_make.arg("all").current_dir(afl_path);
        if let Ok(llvm_config) = env::var("LLVM_CONFIG") {
            if !llvm_config.is_empty() {
                afl_cc_make.env("LLVM_CONFIG", llvm_config);
            }
        }
        afl_cc_make.status().unwrap();
    }

    let mut compile_command = Command::new(afl_cc_path);
    compile_command
        .args(["src/program.c", "-o"])
        .arg(format!("{cwd}/target/release/program"));

    if let Ok(llvm_config) = env::var("LLVM_CONFIG") {
        if !llvm_config.is_empty() {
            compile_command.env("LLVM_CONFIG", llvm_config);
        }
    }

    compile_command.status().unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
}
