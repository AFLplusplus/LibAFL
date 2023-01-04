use crate::options::{LibfuzzerMode, LibfuzzerOptions};

mod fuzz;
mod options;

#[no_mangle]
fn main() {
    let args = Vec::from_iter(std::env::args());
    let options = LibfuzzerOptions::new(args.iter().map(|s| s.as_ref())).unwrap();
    let res = match options.mode() {
        LibfuzzerMode::Fuzz => fuzz::fuzz(options),
        LibfuzzerMode::Merge => {
            unimplemented!()
        }
        LibfuzzerMode::Cmin => {
            unimplemented!()
        }
    };
    res.expect("Encountered error while performing libfuzzer shimming")
}
