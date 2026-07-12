use std::{
    env,
    path::Path,
    process::{exit, Command},
};

const AFL_URL: &str = "https://github.com/AFLplusplus/AFLplusplus";
const AFL_REV: &str = "8b15597d69f91aa0e97562401e7d5410935e665f";

fn main() {
    if cfg!(windows) {
        println!("cargo:warning=No support for windows yet.");
        exit(0);
    }

    env::remove_var("DEBUG");
    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();

    let afl = format!("{}/AFLplusplus", &cwd);
    let afl_gcc = format!("{}/AFLplusplus/afl-cc", &cwd);

    let afl_path = Path::new(&afl);
    let afl_gcc_path = Path::new(&afl_gcc);

    if !afl_path.is_dir() {
        println!("cargo:warning=AFL++ not found, downloading...");
        Command::new("git")
            .arg("clone")
            .arg(AFL_URL)
            .status()
            .unwrap();
        Command::new("git")
            .arg("-C")
            .arg(&afl)
            .arg("checkout")
            .arg(AFL_REV)
            .status()
            .unwrap();
    }

    if !afl_gcc_path.is_file() {
        Command::new("make")
            .arg("all")
            .current_dir(afl_path)
            .status()
            .unwrap();
    }

    Command::new(afl_gcc_path)
        .args(["src/program.c", "-o"])
        .arg(format!("{}/target/release/program", &cwd))
        .arg("-fsanitize=address")
        .status()
        .unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/");
}
