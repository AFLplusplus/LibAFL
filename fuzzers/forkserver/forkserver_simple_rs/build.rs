fn main() {
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-env=TARGET_BIN_PATH={manifest}/target/{profile}/target");
    println!("cargo:rerun-if-changed=build.rs");
}
