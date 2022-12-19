pub mod diffing;
use std::env;

pub use diffing::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    let commits = if args.len() > 1 {
        args[1..].to_vec()
    } else {
        vec!["origin/main".into()]
    };

    let files = get_diffing_files(&commits);
    let mut diff_crates = get_diffing_crates(&files);
    let all_crates = find_all_crates();
    extend_diffing_crates_with_deps(&mut diff_crates, &all_crates);

    let mut fuzzers = vec![];
    for file in diff_crates {
        if file.starts_with("./fuzzers") || file.starts_with("fuzzers") {
            fuzzers.push(file.parent().unwrap().display().to_string());
        }
    }

    println!("{}", fuzzers.join("\n"));
}
