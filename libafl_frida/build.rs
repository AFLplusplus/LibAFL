// build.rs
#![forbid(unexpected_cfgs)]

use std::{env, path::Path};

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "ios" {
        cc::Build::new().file("src/gettls.c").compile("libgettls.a");
    }

    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap();

    // Force linking against libc++
    #[cfg(not(target_vendor = "apple"))]
    if target_family == "unix" {
        println!("cargo:rustc-link-lib=dylib=c++");
    }

    #[cfg(target_vendor = "apple")]
    println!("cargo:rustc-link-lib=dylib=resolv");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=test_harness.cpp");
    println!("cargo:rerun-if-changed=src/gettls.c");
    // Build the test harness
    // clang++ -shared -fPIC -O0 -o test_harness.so test_harness.cpp
    // Check if we have clang++ installed

    if target_family == "windows" {
        let compiler = cc::Build::new()
            .cpp(true)
            .file("test_harness.cpp")
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
        cmd.arg("/dll").arg(format!(
            "/OUT:{}",
            Path::new(&out_dir)
                .join("test_harness.dll")
                .to_str()
                .unwrap()
        ));
        let output = cmd.output().expect("Failed to link test_harness.dll");
        let output_str = format!(
            "{:?}\nstatus: {}\nstdout: {}\nstderr: {}",
            cmd,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        // std::fs::write("compiler_output.txt", output_str.clone()).expect("Unable to write file");
        assert!(
            output.status.success(),
            "Failed to link test_harness.dll\n {:?}",
            output_str.as_str()
        );
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
            .arg(Path::new(&out_dir).join("test_harness.so"))
            .status()
            .expect("Failed to link test_harness");
    }
}
