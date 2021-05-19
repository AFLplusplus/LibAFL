//! build.rs for `libafl_targets`

use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    //let out_dir_path = Path::new(&out_dir);
    let _src_dir = Path::new("src");

    //std::env::set_var("CC", "clang");
    //std::env::set_var("CXX", "clang++");

    #[cfg(any(feature = "sancov_value_profile", feature = "sancov_cmplog"))]
    {
        println!("cargo:rerun-if-changed=src/sancov_cmp.c");

        let mut sancov_cmp = cc::Build::new();

        #[cfg(feature = "sancov_value_profile")]
        sancov_cmp.define("SANCOV_VALUE_PROFILE", "1");

        #[cfg(feature = "sancov_cmplog")]
        sancov_cmp.define("SANCOV_CMPLOG", "1");

        sancov_cmp
            .file(_src_dir.join("sancov_cmp.c"))
            .compile("sancov_cmp");
    }

    #[cfg(feature = "libfuzzer")]
    {
        println!("cargo:rerun-if-changed=src/libfuzzer_compatibility.c");

        cc::Build::new()
            .file(_src_dir.join("libfuzzer_compatibility.c"))
            .compile("libfuzzer_compatibility");
    }

    println!("cargo:rustc-link-search=native={}", &out_dir);

    println!("cargo:rerun-if-changed=build.rs");
}
