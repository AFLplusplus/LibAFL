use std::{io, io::ErrorKind, path::PathBuf, str::from_utf8};

use clap::Parser;
use regex::RegexSet;
use tokio::{process::Command, task::JoinSet};
use walkdir::WalkDir;
use which::which;

async fn run_cargo_fmt(path: PathBuf, is_check: bool, verbose: bool) -> io::Result<()> {
    // Sanity Check
    assert_eq!(path.file_name().unwrap().to_str().unwrap(), "Cargo.toml");

    let task_str = if is_check { "Checking" } else { "Formatting" };

    let mut fmt_command = Command::new("cargo");

    fmt_command
        .arg("+nightly")
        .arg("fmt")
        .arg("--manifest-path")
        .arg(path.as_path());

    if is_check {
        fmt_command.arg("--check");
    }

    if verbose {
        println!("[*] {} {}...", task_str, path.as_path().display());
    }

    let res = fmt_command.output().await?;

    if !res.status.success() {
        println!("{}", from_utf8(&res.stderr).unwrap());
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("Cargo fmt failed. Run cargo fmt for {:#?}", path),
        ));
    }

    Ok(())
}

async fn run_clang_fmt(
    path: PathBuf,
    clang: &str,
    is_check: bool,
    verbose: bool,
) -> io::Result<()> {
    let task_str = if is_check { "Checking" } else { "Formatting" };

    let mut fmt_command = Command::new(clang);

    fmt_command
        .arg("-i")
        .arg("--style")
        .arg("file")
        .arg(path.as_path());

    if is_check {
        fmt_command.arg("-Werror").arg("--dry-run");
    }

    fmt_command.arg(path.as_path());

    if verbose {
        println!("[*] {} {}...", task_str, path.as_path().display());
    }

    let res = fmt_command.output().await?;

    if !res.status.success() {
        println!("{}", from_utf8(&res.stderr).unwrap());
        return Err(io::Error::new(
            ErrorKind::Other,
            format!("{} failed.", clang),
        ));
    }

    Ok(())
}

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    check: bool,
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let libafl_root_dir = match project_root::get_project_root() {
        Ok(p) => p,
        Err(_) => std::env::current_dir()
            .expect("Failed to get current directory")
            .into(),
    };

    println!("Using {:#?} as the project root", libafl_root_dir);
    let rust_excluded_directories = RegexSet::new([
        r".*target.*",
        r".*utils/noaslr.*",
        r".*utils/gdb_qemu.*",
        r".*docs/listings/baby_fuzzer/listing-.*",
        r".*LibAFL/Cargo.toml.*",
        r".*AFLplusplus.*",
    ])
    .expect("Could not create the regex set from the given regex");

    let c_excluded_directories = RegexSet::new([
        r".*target.*",
        r".*libpng-1\.6.*",
        r".*stb_image\.h$",
        r".*dlmalloc\.c$",
        r".*QEMU-Nyx.*",
        r".*AFLplusplus.*",
        r".*cms_transform_fuzzer.cc.*",
    ])
    .expect("Could not create the regex set from the given regex");

    let c_file_to_format = RegexSet::new([
        r".*\.cpp$",
        r".*\.hpp$",
        r".*\.cc$",
        r".*\.cxx$",
        r".*\.c$",
        r".*\.h$",
    ])
    .expect("Could not create the regex set from the given regex");

    let rust_projects_to_fmt: Vec<PathBuf> = WalkDir::new(&libafl_root_dir)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|e| !rust_excluded_directories.is_match(e.path().as_os_str().to_str().unwrap()))
        .filter(|e| e.file_name() == "Cargo.toml")
        .map(|e| e.into_path())
        .collect();

    let mut tokio_joinset = JoinSet::new();

    for project in rust_projects_to_fmt {
        tokio_joinset.spawn(run_cargo_fmt(project, cli.check, cli.verbose));
    }

    let (clang, warning) = if which("clang-format-17").is_ok() {
        // can't use 18 for ci.
        (Some("clang-format-17"), None)
    } else if which("clang-format").is_ok() {
        (
            Some("clang-format"),
            Some("using clang-format, could provide a different result from clang-format-18"),
        )
    } else {
        (
            None,
            Some("clang-format not found. Skipping C formatting..."),
        )
    };

    if let Some(clang) = clang {
        let c_files_to_fmt: Vec<PathBuf> = WalkDir::new(&libafl_root_dir)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|e| !c_excluded_directories.is_match(e.path().as_os_str().to_str().unwrap()))
            .filter(|e| e.file_type().is_file())
            .filter(|e| c_file_to_format.is_match(e.file_name().to_str().unwrap()))
            .map(|e| e.into_path())
            .collect();

        for c_file in c_files_to_fmt {
            tokio_joinset.spawn(run_clang_fmt(c_file, clang, cli.check, cli.verbose));
        }
    }

    while let Some(res) = tokio_joinset.join_next().await {
        match res? {
            Ok(_) => {}
            Err(err) => {
                println!("Error: {}", err);
                std::process::exit(exitcode::IOERR)
            }
        }
    }

    if let Some(warning) = warning {
        println!("Warning: {}", warning);
    }

    if cli.check {
        println!("[*] Check finished successfully.")
    } else {
        println!("[*] Formatting finished successfully.")
    }

    Ok(())
}
