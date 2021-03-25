#[cfg(feature = "sancov")]
pub mod sancov;
#[cfg(feature = "sancov")]
pub use sancov::*;

#[cfg(feature = "libfuzzer_compatibility")]
pub mod libfuzzer_compatibility;
#[cfg(feature = "libfuzzer_compatibility")]
pub use libfuzzer_compatibility::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
