#[rustversion::nightly]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-cfg=unstable_feature");
}

#[rustversion::not(nightly)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
