#![forbid(unexpected_cfgs)]

#[rustversion::nightly]
fn nightly() {
    println!("cargo:rustc-cfg=nightly");
}

#[rustversion::not(nightly)]
fn nightly() {}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(nightly)");
    println!("cargo:rerun-if-changed=build.rs");
    nightly();
}
