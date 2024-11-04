use std::{env, path::PathBuf, str::FromStr};

fn main() -> anyhow::Result<()> {
    if env::var("CARGO_BIN_NAME").map_or(true, |v| v != "libafl_cc") {
        println!("cargo:rerun-if-changed=./first.h");
        println!("cargo:rerun-if-changed=./first.c");
        println!("cargo:rerun-if-changed=./second.h");
        println!("cargo:rerun-if-changed=./second.c");
        println!("cargo:rerun-if-changed=./common.c");

        // Configure and generate bindings.
        let bindings = bindgen::builder()
            .header("first.h")
            .header("second.h")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()?;

        // Write the generated bindings to an output file.
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        bindings
            .write_to_file(out_path.join("bindings.rs"))
            .expect("Couldn't write bindings!");

        let compiler = env::var("CARGO_TARGET_DIR")
            .map_or(PathBuf::from_str("target").unwrap(), |v| {
                PathBuf::from_str(&v).unwrap()
            })
            .join("release/libafl_cc");
        println!("cargo:rerun-if-changed={}", compiler.to_str().unwrap());
        if compiler.try_exists().unwrap_or(false) {
            cc::Build::new()
                .compiler(compiler)
                .file("first.c")
                .file("second.c")
                .file("common.c")
                .compile("diff-target");

            println!("cargo:rustc-link-lib=diff-target");
        } else {
            println!("cargo:warning=Can't find libafl_cc; assuming that we're building it.");
        }
    }

    Ok(())
}
