// build.rs

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "ios" {
        cc::Build::new().file("src/gettls.c").compile("libgettls.a");
    }

    // Force linking against libc++
    #[cfg(unix)]
    println!("cargo:rustc-link-lib=dylib=c++");

    // Build the test harness
    // clang++ -shared -fPIC -o harness.so harness.cpp
    #[cfg(unix)]
    std::process::Command::new("clang++")
        .arg("-shared")
        .arg("-fPIC")
        .arg("-O0")
        .arg("-o")
        .arg("harness.so")
        .arg("harness.cpp")
        .status()
        .expect("Failed to build runtime");
}
