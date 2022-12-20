use std::{error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::var("DOCS_RS").is_ok() {
        return Ok(());
    }
    if cfg!(not(target_os = "linux")) {
        panic!("libafl_verilator is only compatible with Linux.");
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper/wrapper.cpp");
    println!("cargo:rerun-if-changed=wrapper/wrapper.h");

    let bindings = bindgen::builder()
        .header("wrapper/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()?;

    let out_path = PathBuf::from(std::env::var("OUT_DIR")?);
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let mut compiler = cc::Build::new();

    if let Some(inc) = std::env::var_os("VERILATOR_ROOT") {
        let mut path = PathBuf::from(inc);
        path.push("include");
        compiler.include(&path);

        let mut test_compiler = cc::Build::new();
        test_compiler
            .file(path.join("verilated_cov.cpp"))
            .file(path.join("verilated.cpp"))
            .file("wrapper/test-context.cpp")
            .include(&path)
            .define("VL_NO_LEGACY", None)
            .cpp(true)
            .compile("afl-verilator-test");
    }

    compiler
        .file("wrapper/wrapper.cpp")
        .define("VL_NO_LEGACY", None)
        .cpp(true)
        .compile("afl-verilator-wrapper");

    println!("cargo:rustc-link-lib=afl-verilator-wrapper");

    Ok(())
}
