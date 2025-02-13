// build.rs

use std::env;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();

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

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
