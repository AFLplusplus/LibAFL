mod host_specific {
    #[cfg(target_os = "linux")]
    include!("build_linux.rs");

    #[cfg(not(target_os = "linux"))]
    pub fn build() {
        // Print a emulation_mode to silence clippy's unexpected cfg on macOS
        println!("cargo:rustc-cfg=emulation_mode=\"usermode\"");
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
