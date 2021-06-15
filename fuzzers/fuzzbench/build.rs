// build.rs

fn main() {
    cc::Build::new().file("src/libafl_wrapper.c").compile("libafl_sys.a");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/libafl_wrapper.c");
}
    