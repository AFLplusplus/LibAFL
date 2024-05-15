#![forbid(unexpected_cfgs)]

use std::path::PathBuf;

use libafl_qemu_build::build_with_bindings;

// RUST_BACKTRACE=1 OUT_DIR=/tmp/foo/a/b/c cargo run
fn main() {
    let bfile = PathBuf::from("generated_qemu_bindings.rs");
    build_with_bindings("arm", false, false, None, &bfile);
}
