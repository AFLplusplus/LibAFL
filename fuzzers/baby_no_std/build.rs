fn main() {
    #[cfg(unix)]
    println!("cargo:rustc-link-lib=c")
}
