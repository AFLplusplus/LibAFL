#[rustversion::nightly]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-cfg=unstable_feature");
}

#[rustversion::not(nightly)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    assert!(
        cfg!(not(feature = "nautilus")),
        "The 'nautilus' feature of libafl requires a nightly compiler"
    );
}
