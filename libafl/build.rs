#[rustversion::nightly]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-cfg=nightly");
}

#[rustversion::not(nightly)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    assert!(
        cfg!(all(not(docrs), not(feature = "nautilus"))),
        "The 'nautilus' feature of libafl requires a nightly compiler"
    );
}
