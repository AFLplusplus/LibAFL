// build.rs

use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    //let out_dir_path = Path::new(&out_dir);
    let _src_dir = Path::new("src");

    //std::env::set_var("CC", "clang");
    //std::env::set_var("CXX", "clang++");

    #[cfg(feature = "libfuzzer")]
    {
        println!("cargo:rerun-if-changed=src/libfuzzer_compatibility.c");

        cc::Build::new()
            .file(_src_dir.join("libfuzzer_compatibility.c"))
            .compile("libfuzzer_compatibility");
    }

    #[cfg(feature = "value_profile")]
    {
        println!("cargo:rerun-if-changed=src/value_profile.c");

        cc::Build::new()
            .file(_src_dir.join("value_profile.c"))
            .compile("value_profile");
    }

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
