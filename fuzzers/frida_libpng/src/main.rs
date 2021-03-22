#[cfg(unix)]
pub use fuzzer::main;
#[cfg(not(unix))]
pub fn main() {
    todo!("Frida not yet supported on this OS.");
}
