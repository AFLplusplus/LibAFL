#![forbid(unexpected_cfgs)]

#[rustversion::nightly]
fn nightly() {
    println!("cargo:rustc-cfg=nightly");
}

#[rustversion::not(nightly)]
fn nightly() {}

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if cfg!(feature = "intel_pt") && target_os != "linux" {
        println!(
            "cargo:warning=The 'intel_pt' feature is enabled, but this is not a Linux system \
            ({target_os}). The feature will not work."
        );
    }

    println!("cargo:rustc-check-cfg=cfg(nightly)");
    println!("cargo:rerun-if-changed=build.rs");
    nightly();
}
