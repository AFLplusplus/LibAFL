#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(unused_mut)]
#![allow(clippy::all)]

#[cfg(not(feature = "clippy"))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
