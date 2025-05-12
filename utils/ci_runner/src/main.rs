use std::{
    env, fs,
    path::PathBuf,
    process::{Command, exit},
};

fn run() -> Result<(), Box<dyn core::error::Error>> {
    let me = env::args().next().ok_or("no argv[0]")?;
    let exe_path = fs::canonicalize(&me)?;
    let project_dir = exe_path
        .parent()
        .ok_or("failed to get libafl root dir")?
        .parent()
        .ok_or("failed to get libafl root dir")?
        .parent()
        .ok_or("failed to get libafl root dir")?;

    env::set_current_dir(project_dir)?;
    let args: Vec<String> = env::args().collect();
    let mut fuzzers_to_test = Vec::new();

    // take the first arg as the fuzzer name
    if args.len() < 2 {
        eprintln!("Expected fuzzer name as argument when RUN_ON_CI is set");
        exit(1);
    }
    fuzzers_to_test.push(PathBuf::from(&args[1]));
    unsafe {
        env::set_var("PROFILE", "dev");
        env::set_var("PROFILE_DIR", "debug");
    }

    for f in &fuzzers_to_test {
        print!(" {}", f.to_string_lossy());
    }
    println!();

    // 5) set cargo profile envs
    for profile in &["DEV", "RELEASE"] {
        unsafe {
            env::set_var(format!("CARGO_PROFILE_{profile}_OPT_LEVEL"), "z");
            env::set_var(format!("CARGO_PROFILE_{profile}_INCREMENTAL"), "true");
        }
    }

    // 6) for each fuzzer
    for fuzzer in fuzzers_to_test {
        let fuzzer_name = fuzzer.to_string_lossy();
        let name = fuzzer
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_else(|| fuzzer_name.as_ref())
            .to_string();

        let path = project_dir.join(&fuzzer);

        // Clippy
        let do_clippy = args.get(1).is_none_or(|s| s != "--no-clippy");
        if do_clippy {
            println!("[*] Running clippy for {name}");
            let status = Command::new("cargo")
                .arg("clippy")
                .current_dir(&path)
                .status()?;
            if !status.success() {
                exit(1);
            }
        } else {
            println!("[+] Skipping fmt and clippy for {name} (--no-clippy specified)");
        }

        if path.join("Justfile").exists() {
            println!("[*] Testing {name}");
            let status = Command::new("just")
                .arg("test")
                .current_dir(&path)
                .status()?;
            if !status.success() {
                exit(1);
            }
            println!("[+] Done testing {name}");
        } else {
            println!("[*] Building {name}");
            let status = Command::new("cargo")
                .arg("build")
                .current_dir(&path)
                .status()?;
            if !status.success() {
                exit(1);
            }
            println!("[+] Done building {name}");
        }
    }

    Ok(())
}

fn main() {
    run().unwrap();
}
