extern crate cc;

fn main() {
    cc::Build::new().file("src/harness.c").compile("harness.a");
}
