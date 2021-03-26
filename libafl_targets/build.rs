// build.rs

use std::env;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    //let out_dir_path = Path::new(&out_dir);

    std::env::set_var("CC", "clang");
    std::env::set_var("CXX", "clang++");

    #[cfg(feature = "libfuzzer")]
    {
        println!("cargo:rerun-if-changed=libfuzzer_compatibility.c");

        cc::Build::new()
            .file("libfuzzer_compatibility.c")
            .compile("libfuzzer_compatibility");
    }

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
