pub mod diffing;
use std::env;

pub use diffing::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    let commit = if args.len() > 1 { &args[1] } else { "HEAD^" };

    let files = get_diffing_files(commit);
    let mut diff_crates = get_diffing_crates(&files);
    let all_crates = find_all_crates();
    extend_diffing_crates_with_deps(&mut diff_crates, &all_crates);

    for file in diff_crates {
        if file.starts_with("./fuzzers") || file.starts_with("fuzzers") {
            print!("{} ", file.parent().unwrap().display());
        }
    }
}
