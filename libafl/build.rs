use std::error::Error;

#[rustversion::nightly]
#[allow(clippy::unnecessary_wraps)]
fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-cfg=nightly");
    Ok(())
}

#[rustversion::not(nightly)]
#[allow(clippy::unnecessary_wraps)]
fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    assert!(
        cfg!(all(not(docrs), not(feature = "nautilus"))),
        "The 'nautilus' feature of libafl requires a nightly compiler"
    );
    Ok(())
}
