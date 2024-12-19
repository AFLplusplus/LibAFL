//! Address sanitization using [`frida`](https://frida.re/)
pub mod asan_rt;
pub mod errors;

#[allow(missing_docs)] // cfg dependent
pub mod hook_funcs;
