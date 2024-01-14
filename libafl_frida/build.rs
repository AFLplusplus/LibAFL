// build.rs

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "ios" {
        cc::Build::new().file("src/gettls.c").compile("libgettls.a");
    }

    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap();
    // Force linking against libc++
    if target_family == "unix" {
        println!("cargo:rustc-link-lib=dylib=c++");

        // Build the test harness
        // clang++ -shared -fPIC -O0 -o test_harness.so test_harness.cpp
        #[cfg(unix)]
        {
            // Check if we have clang++ installed
            let compiler = cc::Build::new().cpp(true).get_compiler();
            let clangpp = compiler.path();
            std::process::Command::new(clangpp)
                .args(compiler.args())
                .arg("-shared")
                .arg("-fPIC")
                .arg("-O0")
                .arg("-o")
                .arg("test_harness.so")
                .arg("test_harness.cpp")
                .status()
                .expect("Failed to build test harness");
        }
    }
}
