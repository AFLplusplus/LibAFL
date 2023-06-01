// build.rs

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "ios" {
        cc::Build::new().file("src/gettls.c").compile("libgettls.a");
    }

    // Force linking against libc++
    if target_os != "windows" {
        println!("cargo:rustc-link-lib=dylib=c++");
    }
}
