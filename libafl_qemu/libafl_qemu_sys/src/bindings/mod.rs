#![expect(non_upper_case_globals)]
#![expect(non_camel_case_types)]
#![expect(non_snake_case)]
#![expect(clippy::all)]
#![expect(clippy::pedantic)]
#![expect(improper_ctypes)]
#![expect(unsafe_op_in_unsafe_fn)]
#![allow(unused_imports)]

#[cfg(all(not(feature = "clippy"), target_os = "linux"))]
#[rustfmt::skip]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(any(feature = "clippy", not(target_os = "linux")))]
mod x86_64_stub_bindings;
#[cfg(any(feature = "clippy", not(target_os = "linux")))]
pub use x86_64_stub_bindings::*;
