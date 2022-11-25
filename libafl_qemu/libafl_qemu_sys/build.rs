mod host_specific {
    #[cfg(target_os = "linux")]
    include!("build_linux.rs");

    #[cfg(not(target_os = "linux"))]
    pub fn build() {
        println!("cargo:warning=libafl_qemu_sys only builds on Linux hosts ATM");
    }
}

fn main() {
    host_specific::build();
}
