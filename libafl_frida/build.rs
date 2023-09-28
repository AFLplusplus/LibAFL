// build.rs

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "ios" {
        cc::Build::new().file("src/gettls.c").compile("libgettls.a");
    }

    // Force linking against libc++
    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap();
    if target_family == "unix" {
        println!("cargo:rustc-link-lib=dylib=c++");
    }
}
