use std::{env, path::Path};

#[allow(clippy::too_many_lines)]
fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();

    println!("cargo:rerun-if-changed=src/harness_wrap.h");
    println!("cargo:rerun-if-changed=src/harness_wrap.cpp");

    let build = bindgen::builder()
        .header("src/harness_wrap.h")
        .generate_comments(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Couldn't generate the harness wrapper!");

    build
        .write_to_file(Path::new(&out_dir).join("harness_wrap.rs"))
        .expect("Couldn't write the harness wrapper!");

    cc::Build::new()
        .cpp(true)
        .file("src/harness_wrap.cpp")
        .compile("harness_wrap");
}
