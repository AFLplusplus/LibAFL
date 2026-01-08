use std::env;
use std::process::{Command, exit};

fn main() {
    // Get the script directory
    let script_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .expect("Failed to get script directory");
    let workspace_dir = script_dir.parent().unwrap_or(&script_dir);
    if env::set_current_dir(workspace_dir).is_err() {
        eprintln!("Failed to change directory to workspace root");
        exit(1);
    }

    println!("Welcome to the happy clean script. :)");
    println!("[*] Running clean for the main crates");
    let _ = Command::new("cargo").arg("clean").status();

    // Use the system `find` so stderr (e.g. "No such file or directory") matches the shell script
    fn find_dirs(path: &str) -> Vec<std::path::PathBuf> {
        let out = Command::new("find")
            .arg(path)
            .arg("-maxdepth")
            .arg("1")
            .arg("-type")
            .arg("d")
            .output();

        match out {
            Ok(o) => {
                if !o.stderr.is_empty() {
                    eprint!("{}", String::from_utf8_lossy(&o.stderr));
                }
                let s = String::from_utf8_lossy(&o.stdout);
                s.lines().map(|l| std::path::Path::new(l).to_path_buf()).collect()
            }
            Err(e) => {
                eprintln!("failed to run find: {}", e);
                Vec::new()
            }
        }
    }

    let fuzzers = find_dirs("./fuzzers");
    let backtrace_fuzzers = find_dirs("./fuzzers/backtrace_baby_fuzzers");

    for fuzzer in fuzzers.iter().chain(backtrace_fuzzers.iter()) {
        if fuzzer.is_dir() {
            // emulate `pushd` output: new_dir + workspace_dir
            println!("{} {}", fuzzer.display(), workspace_dir.display());

            if env::set_current_dir(fuzzer).is_err() {
                eprintln!("Failed to enter {}", fuzzer.display());
                continue;
            }

            println!("[*] Running clean for {}", fuzzer.display());
            let _ = Command::new("cargo").arg("clean").status();

            // emulate `popd` output: workspace_dir
            println!("{}", workspace_dir.display());

            if env::set_current_dir(workspace_dir).is_err() {
                eprintln!("Failed to return to workspace root");
                exit(1);
            }
        }
    }
}



// README

// - first we will compile the rust file
//     rustc scripts/clean_all.rs -o scripts/clean_all

// - now we have the executable which we will run
//     ./scripts/clean_all



