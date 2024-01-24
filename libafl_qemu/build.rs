mod host_specific {
    #[cfg(target_os = "linux")]
    include!("build_linux.rs");

    #[cfg(not(target_os = "linux"))]
    pub fn build() {
        println!("cargo:warning=libafl_qemu only builds on Linux hosts");
    }
}

#[rustversion::nightly]
fn main() {
    println!("cargo:rustc-cfg=nightly");
    host_specific::build();
}

#[rustversion::not(nightly)]
fn main() {
    host_specific::build();
}
