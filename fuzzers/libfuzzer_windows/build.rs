// build.rs

#[cfg(windows)]
use std::env;

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
        .flag("-Wno-void-pointer-to-int-cast")
        .flag("-Wno-pointer-to-int-cast")
        .flag("-Wno-int-to-pointer-cast")
        .flag("-Wno-sign-compare")
        .flag("-Wno-format")
        .flag("-Wno-unused-variable")
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
