// build.rs

use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy();

    println!("cargo:rerun-if-changed=./runtime/rt.c",);
    Command::new("clang")
        .args(&["-c", "./runtime/rt.c", "-o"])
        .arg(&format!("{:?}/rt.o", out_dir))
        .status()
        .unwrap();
    Command::new("ar")
        .args(&["crus", "librt.a", "librt.o"])
        .current_dir(&Path::new(out_dir.as_ref()))
        .status()
        .unwrap();

    println!("cargo:rerun-if-changed=harness.c");
    Command::new("clang")
        .args(&["-c", "./harness.c", "-I./libpng-1.6.37", "-o"])
        .arg(&format!("{}/harness.o", out_dir))
        .status()
        .unwrap();
    Command::new("ar")
        .args(&["crus", "harness.a", "harness.o"])
        .current_dir(&Path::new(out_dir.as_ref()))
        .status()
        .unwrap();

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=libpng16");
    println!("cargo:rustc-link-lib=static=harness");
    println!("cargo:rustc-link-lib=static=rt");

    println!("cargo:rerun-if-changed=libpng16.a");

    println!("cargo:rerun-if-changed=build.rs");
}
