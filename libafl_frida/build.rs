// build.rs
#![forbid(unexpected_cfgs)]

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "ios" {
        cc::Build::new().file("src/gettls.c").compile("libgettls.a");
    }

    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap();
    // Force linking against libc++
    if target_family == "unix" {
        println!("cargo:rustc-link-lib=dylib=c++");
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=test_harness.cpp");
    println!("cargo:rerun-if-changed=src/gettls.c");
    // Build the test harness
    // clang++ -shared -fPIC -O0 -o test_harness.so test_harness.cpp
    // Check if we have clang++ installed

    if target_family == "windows" {
        let compiler = cc::Build::new()
            .cpp(true)
            .file("test_harness.a")
            .get_compiler();
        let mut cmd = std::process::Command::new(compiler.path());
        let cmd = cmd
            .args(compiler.args())
            .arg("test_harness.cpp")
            .arg("/link");

        #[cfg(unix)]
        let cmd = cmd
            .arg(format!(
                "/libpath:{}/.cache/cargo-xwin/xwin/crt/lib/x86_64/",
                std::env::var("HOME").unwrap()
            ))
            .arg(format!(
                "/libpath:{}/.cache/cargo-xwin/xwin/sdk/lib/ucrt/x86_64/",
                std::env::var("HOME").unwrap()
            ))
            .arg(format!(
                "/libpath:{}/.cache/cargo-xwin/xwin/sdk/lib/um/x86_64/",
                std::env::var("HOME").unwrap()
            ));
        cmd.arg("/dll").arg("/OUT:test_harness.dll");
        cmd.status().expect("Failed to link test_harness.dll");
    } else {
        let compiler = cc::Build::new()
            .cpp(true)
            .opt_level(0)
            .shared_flag(true)
            .get_compiler();
        let clangpp = compiler.path();
        let mut cmd = std::process::Command::new(clangpp);
        cmd.args(compiler.args())
            .arg("test_harness.cpp")
            .arg("-o")
            .arg("test_harness.so")
            .status()
            .expect("Failed to link test_harness");
    }
}
