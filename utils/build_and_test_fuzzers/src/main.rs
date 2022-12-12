pub mod diffing;
pub use diffing::*;

fn main() {
    let files = get_diffing_files("HEAD^");
    let mut diff_crates = get_diffing_crates(&files);
    let all_crates = find_all_crates();
    extend_diffing_crates_with_deps(&mut diff_crates, &all_crates);

    for file in diff_crates {
        if file.starts_with("./fuzzers") || file.starts_with("fuzzers") {
            print!("{} ", file.parent().unwrap().display());
        }
    }
}
