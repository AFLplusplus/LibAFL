#[cfg(target_os = "linux")]
pub mod fuzzer;

fn main() {
    #[cfg(target_os = "linux")]
    fuzzer::main();
}
