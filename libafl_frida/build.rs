// build.rs

fn main() {
    cc::Build::new().file("src/gettls.c").compile("libgettls.a");

    // Force linking against libc++
    println!("cargo:rustc-link-lib=dylib=c++");
}
