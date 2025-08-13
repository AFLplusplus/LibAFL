#![expect(non_upper_case_globals)]
#![expect(non_camel_case_types)]
#![expect(non_snake_case)]
#![expect(unused)]
#![expect(clippy::all)]
#![expect(clippy::pedantic)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(warnings)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
