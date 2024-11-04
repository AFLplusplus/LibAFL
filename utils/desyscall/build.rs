// build.rs

use std::env;

fn main() {
    if cfg!(not(target_os = "linux")) {
        println!("cargo:warning=Not supported!");
        return;
    }

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();

    println!("cargo:rerun-if-changed=src/syscalls.c");

    // Enforce clang for its -fsanitize-coverage support.
    env::set_var("CC", "clang");
    env::set_var("CXX", "clang++");

    cc::Build::new().file("src/syscalls.c").compile("syscalls");
    println!("cargo:rerun-if-changed=src/syscalls.c");

    cc::Build::new().file("src/patch.c").compile("patch");
    println!("cargo:rerun-if-changed=src/patch.c");

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
