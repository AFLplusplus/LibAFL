// build.rs

use std::env;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    //let out_dir_path = Path::new(&out_dir);

    #[cfg(feature = "libfuzzer_compatibility")]
    {
        println!("cargo:rerun-if-changed=libfuzzer_compatibility.c");

        cc::Build::new()
            .file("libfuzzer_compatibility.c")
            .compile("libfuzzer-compatibility");
    }

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
