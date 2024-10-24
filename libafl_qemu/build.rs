mod host_specific {
    #[cfg(target_os = "linux")]
    include!("build_linux.rs");

    #[cfg(not(target_os = "linux"))]
    pub fn build() {
        println!("cargo:warning=libafl_qemu only builds on Linux hosts");
    }
}

#[rustversion::nightly]
fn nightly() {
    println!("cargo:rustc-cfg=nightly");
}

#[rustversion::not(nightly)]
fn nightly() {}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(nightly)");
    nightly();
    host_specific::build();
}
