#![forbid(unexpected_cfgs)]

#[rustversion::nightly]
fn nightly() {
    println!("cargo:rustc-cfg=nightly");
}

#[rustversion::not(nightly)]
fn nightly() {}

fn main() {
    // `msvcrt` is the dynamically-linked C runtime. Do not link it when the
    // target is built with `-C target-feature=+crt-static`: the static CRT
    // (`libcmt`) is already in the link, and mixing both makes the MSVC
    // linker emit LNK4098 and can give the process two separate CRT heaps.
    let crt_static = std::env::var("CARGO_CFG_TARGET_FEATURE")
        .is_ok_and(|features| features.contains("crt-static"));
    if cfg!(target_os = "windows") && !crt_static {
        println!("cargo:rustc-link-lib=msvcrt");
    }
    println!("cargo:rustc-check-cfg=cfg(nightly)");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_FEATURE");
    nightly();
}
