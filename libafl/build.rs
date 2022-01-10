#[rustversion::nightly]
fn main() {
    println!("cargo:rustc-cfg=unstable_feature");
}

#[rustversion::not(nightly)]
fn main() {}
