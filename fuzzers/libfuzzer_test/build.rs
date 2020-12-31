// build.rs

use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let _cwd = env::current_dir().unwrap().to_string_lossy().to_string();
    let out_dir = out_dir.to_string_lossy().to_string();
    let _out_dir_path = Path::new(&out_dir);

    println!("cargo:rerun-if-changed=../libfuzzer_runtime/rt.c",);
    println!("cargo:rerun-if-changed=./test/test.c");

    // We need clang for pc-guard support
    std::env::set_var("CC", "clang");

    cc::Build::new()
        .file("../libfuzzer_runtime/rt.c")
        .compile("libfuzzer-sys-rt");

    cc::Build::new()
        .file("./test/test.c")
        .flag("-fsanitize-coverage=trace-pc-guard,trace-cmp")
        .compile("libfuzzer-sys-target");

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
