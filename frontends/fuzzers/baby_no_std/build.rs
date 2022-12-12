fn main() {
    if std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default() == "unix" {
        println!("cargo:rustc-link-lib=c");
    };
}
