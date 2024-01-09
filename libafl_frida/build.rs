// build.rs

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "ios" {
        cc::Build::new().file("src/gettls.c").compile("libgettls.a");
    }

    // Force linking against libc++
    #[cfg(unix)]
    println!("cargo:rustc-link-lib=dylib=c++");

    // Build the test harness
    // clang++ -shared -fPIC -O0 -o test_harness.so test_harness.cpp
    #[cfg(unix)]
    {
        // Check if we have clang++ installed
        let clangpp = std::process::Command::new("clang++")
            .arg("--version")
            .output();

        match clangpp {
            Ok(_) => {
                std::process::Command::new("clang++")
                    .arg("-shared")
                    .arg("-fPIC")
                    .arg("-O0")
                    .arg("-o")
                    .arg("test_harness.so")
                    .arg("test_harness.cpp")
                    .status()
                    .expect("Failed to build test harness");
            }
            Err(_) => {
                println!("cargo:warning=clang++ not found, skipping test harness build");
            }
        }
    }
}
