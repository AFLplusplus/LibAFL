use std::{path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=libafl_libfuzzer_runtime/src");
    println!("cargo:rerun-if-changed=libafl_libfuzzer_runtime/Cargo.toml");

    let mut lib_path = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    lib_path.push("libafl_libfuzzer_runtime");

    let mut command = Command::new(std::env::var_os("CARGO").unwrap());
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .current_dir(&lib_path);

    lib_path.push("target");
    lib_path.push(std::env::var_os("TARGET").unwrap());
    lib_path.push("release");

    if rustversion::cfg!(nightly) {
        command.arg("-Zbuild-std");
    }

    command
        .arg("build")
        .arg("--release")
        .arg("--target-dir")
        .arg(PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("runtime-target"))
        .arg("--target")
        .arg(std::env::var_os("TARGET").unwrap());

    if command.status().map(|s| !s.success()).unwrap_or(true) {
        panic!("Couldn't build runtime crate! Did you remember to use nightly?");
    }

    println!(
        "cargo:link-lib-search=native={}",
        lib_path.to_str().unwrap()
    );
    println!("cargo:link-lib=static=afl_libfuzzer_runtime");
}
