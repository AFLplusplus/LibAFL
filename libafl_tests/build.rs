use std::env;
use std::path::Path;
use std::process::Command;

const AFL_URL: &str = "https://github.com/google/AFL.git";

fn main() {
    //let out_dir = env::var_os("OUT_DIR").unwrap().to_string_lossy().to_string();
    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();

    let afl = format!("{}/AFL", &cwd);
    let afl_gcc = format!("{}/AFL/afl-gcc", &cwd);

    let afl_path = Path::new(&afl);
    let afl_gcc_path = Path::new(&afl_gcc);

    if !afl_path.is_dir() {
        println!("cargo:warning=AFL not found, downloading...");
        Command::new("git")
            .arg("clone")
            .arg(AFL_URL)
            .status()
            .unwrap();
    }

    if !afl_gcc_path.is_file() {
        Command::new("make")
            .current_dir(&afl_path)
            .status()
            .unwrap();
    }

    Command::new(afl_gcc_path)
        .args(&["src/forkserver_test.c", "-o"])
        .arg(&format!("{}/forkserver_test.o", "src"))
        .status()
        .unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
}
