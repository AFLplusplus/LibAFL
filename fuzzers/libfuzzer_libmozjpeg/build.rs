// build.rs

use std::env;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();

    println!("cargo:rerun-if-changed=harness.c");

    cc::Build::new()
        // Use sanitizer coverage to track the edges in the PUT
        // Take advantage of LTO (needs lld-link set in your cargo config)
        //.flag("-flto=thin")
        .file("./hook_allocs.c")
        .compile("hook_allocs");

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
