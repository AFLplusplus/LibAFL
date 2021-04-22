// build.rs

fn main() {
    #[cfg(target_arch = "aarch64")]
    cc::Build::new().file("src/gettls.c").compile("libgettls.a");
}
