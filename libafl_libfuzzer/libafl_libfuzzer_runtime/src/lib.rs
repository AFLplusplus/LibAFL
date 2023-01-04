use libafl::state::State;
use libafl_targets::*;

use crate::options::LibfuzzerOptions;

mod options;

#[no_mangle]
fn main() {
    let args = Vec::from_iter(std::env::args());
    let options = LibfuzzerOptions::new(args.iter().map(|s| s.as_ref())).unwrap();
    println!("{:?}", options);
}
