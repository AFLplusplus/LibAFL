use std::{env, path::Path};

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    let src_dir = Path::new("src");

    println!("cargo:rerun-if-changed=src/weaks.c");

    cc::Build::new()
        .file(src_dir.join("weaks.c"))
        .compile("weaks");

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
