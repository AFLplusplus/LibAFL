// build.rs

#[cfg(windows)]
use std::{env, path::Path};

#[cfg(not(windows))]
fn main() {
    println!("cargo:warning=Skipping libpng windows example on non-Windows");
    return;
}

#[cfg(windows)]
fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();

    println!("cargo:rerun-if-changed=../libfuzzer_runtime/rt.c",);
    println!("cargo:rerun-if-changed=harness.cc");

    // Enforce clang for its -fsanitize-coverage support.
    std::env::set_var("CC", "clang");
    std::env::set_var("CXX", "clang++");
    /*let ldflags = match env::var("LDFLAGS") {
        Ok(val) => val,
        Err(_) => "".to_string(),
    };*/

    cc::Build::new()
        .file("../libfuzzer_runtime/rt.c")
        .compile("libfuzzer-sys");

    cc::Build::new()
        .cpp(true)
        .flag("-fsanitize-coverage=trace-pc-guard")
        // .define("HAS_DUMMY_CRASH", "1")
        .file("./harness.cc")
        .compile("windows-harness");

    println!("cargo:rustc-link-search=native={}", &out_dir);
    //println!("cargo:rustc-link-search=native={}/.libs", &libpng);
    //println!("cargo:rustc-link-lib=static=png16");

    //Deps for libpng: -pthread -lz -lm
    //println!("cargo:rustc-link-lib=dylib=m");
    //println!("cargo:rustc-link-lib=dylib=z");

    //For the C++ harness
    //must by dylib for android
    //println!("cargo:rustc-link-lib=dylib=stdc++");

    println!("cargo:rerun-if-changed=build.rs");
}
