#[rustversion::nightly]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-cfg=nightly");
    #[cfg(target_env = "musl")]
    println!("cargo:rustc-link-lib=ucontext");
}

#[rustversion::not(nightly)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(target_env = "musl")]
    println!("cargo:rustc-link-lib=ucontext");
}
