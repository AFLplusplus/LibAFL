#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused_mut)]
#![allow(unused)]
#![allow(unused_variables)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(improper_ctypes)]

#[cfg(all(not(feature = "clippy"), target_os = "linux"))]
#[rustfmt::skip]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(any(feature = "clippy", not(target_os = "linux")))]
mod x86_64_stub_bindings;
#[cfg(any(feature = "clippy", not(target_os = "linux")))]
pub use x86_64_stub_bindings::*;
