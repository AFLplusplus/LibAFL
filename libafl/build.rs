#[rustversion::nightly]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-cfg=unstable_feature");
}

#[rustversion::not(nightly)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if cfg!(feature = "nautilus") {
        panic!("The 'nautilus' feature of libafl requires a nightly compiler");
    }
}
