// build.rs

fn main() {
    cc::Build::new().file("src/gettls.c").compile("libgettls.a");

    // Force linking against libc++
    #[cfg(unix)]
    println!("cargo:rustc-link-lib=dylib=c++");
}
