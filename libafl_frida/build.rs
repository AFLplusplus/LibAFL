// build.rs
#![forbid(unexpected_cfgs)]
#![allow(deprecated)]
use {
    anyhow::{anyhow, Result},
    bindgen::CargoCallbacks,
    reqwest::blocking::get,
    std::{env, io::Cursor, path::Path},
    tar::Archive,
    xz2::read::XzDecoder,
};

fn extract() -> Result<()> {
    let url = "https://github.com/frida/frida/releases/download/16.2.1/frida-gumjs-devkit-16.2.1-linux-x86_64.tar.xz";
    let response = get(url)?;
    let mut content = Cursor::new(response.bytes()?);
    let xz = XzDecoder::new(&mut content);
    let mut archive = Archive::new(xz);
    let out_dir = env::var("OUT_DIR")?;
    let dest_path = Path::new(&out_dir);

    let mut found_header = false;
    let mut found_lib = false;

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        println!("path: {:?}", path);
        if let Some(filename) = path.file_name() {
            if let Some(name) = filename.to_str() {
                match name {
                    "frida-gumjs.h" => {
                        println!("Extracting header file: {}", name);
                        let full_name = dest_path.join(path);
                        entry.unpack(full_name.as_path())?;
                        found_header = true;
                    }
                    "libfrida-gumjs.a" => {
                        println!("Extracting header file: {}", name);
                        let full_name = dest_path.join(path);
                        entry.unpack(full_name.as_path())?;
                        found_lib = true;
                    }
                    _ => continue,
                }
            }
        }
    }

    if found_header && found_lib {
        Ok(())
    } else {
        Err(anyhow!("Failed to find header in devkit"))
    }
}

fn bindings() -> Result<()> {
    let out_dir = env::var("OUT_DIR")?;
    let dest_path = Path::new(&out_dir);
    let header = dest_path.join("frida-gumjs.h");
    let bindings = bindgen::Builder::default()
        .header(
            header
                .to_str()
                .ok_or(anyhow!("Failed to convert header path"))?,
        )
        .generate_comments(true)
        .generate_inline_functions(true)
        .parse_callbacks(Box::new(CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(dest_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rustc-link-search=native={out_dir:}");
    println!("cargo:rustc-link-lib=static=frida-gumjs");
    /* The GumJS devkit includes v8 (for supported platforms), which is implemented in C++. */
    println!("cargo:rustc-link-lib=dylib=stdc++");
    Ok(())
}

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
        cmd.arg("/dll").arg("/OUT:test_harness.dll");
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
            .arg("test_harness.so")
            .status()
            .expect("Failed to link test_harness");
    }

    extract().unwrap();
    bindings().unwrap();
}
