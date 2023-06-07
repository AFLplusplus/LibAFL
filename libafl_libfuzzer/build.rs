use std::{path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=libafl_libfuzzer_runtime/src");
    println!("cargo:rerun-if-changed=libafl_libfuzzer_runtime/Cargo.toml");

    let custom_lib_dir =
        PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("libafl_libfuzzer");
    std::fs::create_dir_all(&custom_lib_dir)
        .expect("Couldn't create the output directory for the fuzzer runtime build");

    let mut lib_src = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    lib_src.push("libafl_libfuzzer_runtime");

    let mut command = Command::new(std::env::var_os("CARGO").unwrap());
    command
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS");

    for (var, _) in std::env::vars() {
        if var.starts_with("CARGO_PKG_") || var.starts_with("CARGO_FEATURE_") {
            command.env_remove(var);
        }
    }

    command
        .env("PATH", std::env::var_os("PATH").unwrap())
        .current_dir(&lib_src);

    command.arg("build");

    if cfg!(any(feature = "merge", feature = "introspection")) {
        command.arg("--features");
        if cfg!(feature = "merge") {
            command.arg("merge");
        }
        if cfg!(feature = "introspection") {
            command.arg("libafl/introspection");
        }
    }

    command
        .arg("--release")
        .arg("--no-default-features")
        .arg("--target-dir")
        .arg(&custom_lib_dir)
        .arg("--target")
        .arg(std::env::var_os("TARGET").unwrap());

    if command.status().map(|s| !s.success()).unwrap_or(true) {
        panic!("Couldn't build runtime crate! Did you remember to use nightly?");
    }

    let mut lib_path = custom_lib_dir.join(std::env::var_os("TARGET").unwrap());
    lib_path.push("release");
    lib_path.push("libafl_libfuzzer_runtime.a");

    // // TODO this is definitely not compat with macOS/Windows...
    if cfg!(feature = "whole-archive") {
        let mut command = Command::new("ld");
        command
            .arg("-Ur")
            .arg("--whole-archive")
            .arg(lib_path)
            .args(["-o", custom_lib_dir.join("libFuzzer.o").to_str().expect("Invalid path characters present in your current directory prevent us from linking to the runtime")]);

        if command.status().map(|s| !s.success()).unwrap_or(true) {
            panic!("Couldn't link runtime crate!");
        }

        let mut command = Command::new("ar");
        command
            .arg("cr")
            .arg(custom_lib_dir.join("libFuzzer.a"))
            .arg(custom_lib_dir.join("libFuzzer.o"));

        if command.status().map(|s| !s.success()).unwrap_or(true) {
            panic!("Couldn't create runtime archive!");
        }
    } else {
        std::fs::copy(lib_path, custom_lib_dir.join("libFuzzer.a")).unwrap();
    }

    println!(
        "cargo:rustc-link-search=native={}",
        custom_lib_dir.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=Fuzzer");
    println!("cargo:rustc-link-lib=stdc++")
}
