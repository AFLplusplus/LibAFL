use std::env;
use std::fs;
use std::path::Path;
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

    let fuzzers = fs::read_dir("./fuzzers")
        .map(|dirs| dirs.filter_map(|d| d.ok()).map(|d| d.path()).collect::<Vec<_>>())
        .unwrap_or_default();
    let backtrace_fuzzers = fs::read_dir("./fuzzers/backtrace_baby_fuzzers")
        .map(|dirs| dirs.filter_map(|d| d.ok()).map(|d| d.path()).collect::<Vec<_>>())
        .unwrap_or_default();

    for fuzzer in fuzzers.iter().chain(backtrace_fuzzers.iter()) {
        if fuzzer.is_dir() {
            if env::set_current_dir(fuzzer).is_err() {
                eprintln!("Failed to enter {:?}", fuzzer);
                continue;
            }
            println!("[*] Running clean for {:?}", fuzzer);
            let _ = Command::new("cargo").arg("clean").status();
            if env::set_current_dir(workspace_dir).is_err() {
                eprintln!("Failed to return to workspace root");
                exit(1);
            }
        }
    }
}
