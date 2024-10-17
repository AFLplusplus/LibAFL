use std::{env, path::Path, process::Command};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    // Compile the fuzzer target program
    let target_program_out_dir = Path::new(&out_dir).ancestors().nth(3).unwrap();
    let out = Command::new("rustc")
        .args([
            "src/target_program.rs",
            "--out-dir",
            target_program_out_dir.to_str().unwrap(),
            "-C",
            "panic=abort",
            "-O",
        ])
        .output();
    match out {
        Err(e) => {
            println!("cargo:warning=Target program compilation failed with error: {e}");
            panic!("Target program compilation failed.");
        }
        Ok(o) if !o.status.success() => {
            println!("cargo:warning=Target program compilation failed.");
            println!(
                "cargo:warning=Stderr: {} ",
                String::from_utf8(o.stderr).unwrap_or("".to_string())
            );
            println!(
                "cargo:warning=Stdout: {} ",
                String::from_utf8(o.stdout).unwrap_or("".to_string())
            );
            panic!("Target program compilation failed.");
        }
        Ok(_) => {}
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/target_program.rs");
}
