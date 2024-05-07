#![forbid(unexpected_cfgs)]

#[rustversion::nightly]
fn nightly() {
    println!("cargo:rustc-cfg=nightly");
}

#[rustversion::not(nightly)]
fn nightly() {
    assert!(
        cfg!(all(not(docrs), not(feature = "nautilus"))),
        "The 'nautilus' feature of libafl requires a nightly compiler"
    );
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(nightly)");
    println!("cargo:rerun-if-changed=build.rs");
    nightly();
}
