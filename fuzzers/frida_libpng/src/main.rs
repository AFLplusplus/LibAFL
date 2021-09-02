mod fuzzer;
pub fn main() {
    fuzzer::main();
}

/*
#[cfg(not(unix))]
pub fn main() {
    todo!("Frida not yet supported on this OS.");
}
*/
