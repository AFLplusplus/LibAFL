// build.rs

fn main() {
    cc::Build::new().file("src/gettls.c").compile("libgettls.a");
}
