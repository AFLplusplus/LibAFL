//! special handling to build and link libafl

use rustc_version::{version_meta, Channel};

#[allow(clippy::ptr_arg, clippy::upper_case_acronyms)]
fn main() {

    // Set cfg flags depending on release channel
    match version_meta().unwrap().channel {
        Channel::Stable => {
            println!("cargo:rustc-cfg=RUSTC_IS_STABLE");
        }
        Channel::Beta => {
            println!("cargo:rustc-cfg=RUSTC_IS_BETA");
        }
        Channel::Nightly => {
            println!("cargo:rustc-cfg=RUSTC_IS_NIGHTLY");
        }
        Channel::Dev => {
            println!("cargo:rustc-cfg=RUSTC_IS_DEV");
        }
    }
}
