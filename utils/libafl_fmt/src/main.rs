/*!
 * # `LibAFL` fmt
 *
 * Formatting `LibAFL` since 2024
 */
#![forbid(unexpected_cfgs)]
#![allow(incomplete_features)]
#![warn(clippy::cargo)]
#![allow(ambiguous_glob_reexports)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(
    clippy::unreadable_literal,
    clippy::type_repetition_in_bounds,
    clippy::missing_errors_doc,
    clippy::cast_possible_truncation,
    clippy::used_underscore_binding,
    clippy::ptr_as_ptr,
    clippy::missing_panics_doc,
    clippy::missing_docs_in_private_items,
    clippy::module_name_repetitions,
    clippy::ptr_cast_constness,
    clippy::unsafe_derive_deserialize,
    clippy::similar_names,
    clippy::too_many_lines
)]
#![cfg_attr(not(test), warn(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
))]
#![cfg_attr(test, deny(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    //unused_results
))]
#![cfg_attr(
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        no_mangle_generic_items,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]
// Till they fix this buggy lint in clippy
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::borrow_deref_ref)]

use std::{
    fs::read_to_string,
    io,
    io::ErrorKind,
    path::{Path, PathBuf},
    str::from_utf8,
};

use clap::Parser;
use colored::Colorize;
use regex::RegexSet;
use tokio::{process::Command, task::JoinSet};
use walkdir::{DirEntry, WalkDir};
use which::which;

const REF_LLVM_VERSION: u32 = 19;

fn is_workspace_toml(path: &Path) -> bool {
    for line in read_to_string(path).unwrap().lines() {
        if line.eq("[workspace]") {
            return true;
        }
    }

    false
}

async fn run_cargo_fmt(cargo_file_path: PathBuf, is_check: bool, verbose: bool) -> io::Result<()> {
    // Make sure we parse the correct file
    assert_eq!(
        cargo_file_path.file_name().unwrap().to_str().unwrap(),
        "Cargo.toml"
    );

    if is_workspace_toml(cargo_file_path.as_path()) {
        println!("[*] Skipping {}...", cargo_file_path.as_path().display());
        return Ok(());
    }

    let task_str = if is_check { "Checking" } else { "Formatting" };

    let mut fmt_command = Command::new("cargo");

    fmt_command
        .arg("+nightly")
        .arg("fmt")
        .arg("--manifest-path")
        .arg(cargo_file_path.as_path());

    if is_check {
        fmt_command.arg("--check");
    }

    if verbose {
        println!(
            "[*] {} {}...",
            task_str,
            cargo_file_path.as_path().display()
        );
    }

    let res = fmt_command.output().await?;

    if !res.status.success() {
        let stdout = from_utf8(&res.stdout).unwrap();
        let stderr = from_utf8(&res.stderr).unwrap();
        return Err(io::Error::new(
            ErrorKind::Other,
            format!(
                "Cargo fmt failed. Run cargo fmt for {cargo_file_path:#?}.\nstdout: {stdout}\nstderr: {stderr}\ncommand: {fmt_command:?}"),
        ));
    }

    Ok(())
}

async fn run_clang_fmt(
    c_file_path: PathBuf,
    clang: String,
    is_check: bool,
    verbose: bool,
) -> io::Result<()> {
    let task_str = if is_check { "Checking" } else { "Formatting" };

    let mut fmt_command = Command::new(&clang);

    fmt_command
        .arg("-i")
        .arg("--style")
        .arg("file")
        .arg(c_file_path.as_path());

    if is_check {
        fmt_command.arg("-Werror").arg("--dry-run");
    }

    fmt_command.arg(c_file_path.as_path());

    if verbose {
        println!("[*] {} {}...", task_str, c_file_path.as_path().display());
    }

    let res = fmt_command.output().await?;

    if res.status.success() {
        Ok(())
    } else {
        let stdout = from_utf8(&res.stdout).unwrap();
        let stderr = from_utf8(&res.stderr).unwrap();
        println!("{stderr}");
        Err(io::Error::new(
            ErrorKind::Other,
            format!("{clang} failed.\nstdout:{stdout}\nstderr:{stderr}"),
        ))
    }
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
        Err(_) => std::env::current_dir().expect("Failed to get current directory"),
    };

    println!("Using {libafl_root_dir:#?} as the project root");
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
        r".*Little-CMS.*",
        r".*cms_transform_fuzzer.cc.*",
        r".*sqlite3.*",
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
        .filter_map(Result::ok)
        .filter(|e| !rust_excluded_directories.is_match(e.path().as_os_str().to_str().unwrap()))
        .filter(|e| e.file_name() == "Cargo.toml")
        .map(DirEntry::into_path)
        .collect();

    // cargo version
    println!(
        "Using {}",
        get_version_string("cargo", &["+nightly"]).await?
    );

    // rustfmt version
    println!(
        "Using {}",
        get_version_string("cargo", &["+nightly", "fmt"]).await?
    );

    let reference_clang_format = format!(
        "clang-format-{}",
        std::env::var("MAIN_LLVM_VERSION")
            .inspect(|e| {
                println!(
                    "Overriding clang-format version from the default {REF_LLVM_VERSION} to {e} using env variable MAIN_LLVM_VERSION"
                );
            })
            .unwrap_or(REF_LLVM_VERSION.to_string())
    );
    let unspecified_clang_format = "clang-format";

    let (clang, version, warning) = if which(&reference_clang_format).is_ok() {
        (
            Some(reference_clang_format.as_str()),
            Some(get_version_string(&reference_clang_format, &[]).await?),
            None,
        )
    } else if which(unspecified_clang_format).is_ok() {
        let version = get_version_string(unspecified_clang_format, &[]).await?;
        (
            Some(unspecified_clang_format),
            Some(version.clone()),
            Some(format!(
                "using {version}, could provide a different result from {reference_clang_format}"
            )),
        )
    } else {
        (
            None,
            None,
            Some("clang-format not found. Skipping C formatting...".to_string()),
        )
    };

    if let Some(version) = &version {
        println!("Using {version}");
    }

    let mut tokio_joinset = JoinSet::new();

    for project in rust_projects_to_fmt {
        tokio_joinset.spawn(run_cargo_fmt(project, cli.check, cli.verbose));
    }

    if let Some(clang) = clang {
        let c_files_to_fmt: Vec<PathBuf> = WalkDir::new(&libafl_root_dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| !c_excluded_directories.is_match(e.path().as_os_str().to_str().unwrap()))
            .filter(|e| e.file_type().is_file())
            .filter(|e| c_file_to_format.is_match(e.file_name().to_str().unwrap()))
            .map(DirEntry::into_path)
            .collect();

        for c_file in c_files_to_fmt {
            tokio_joinset.spawn(run_clang_fmt(
                c_file,
                clang.to_string(),
                cli.check,
                cli.verbose,
            ));
        }
    }

    while let Some(res) = tokio_joinset.join_next().await {
        match res? {
            Ok(()) => {}
            Err(err) => {
                println!("Error: {err}");
                std::process::exit(exitcode::IOERR)
            }
        }
    }

    let _ = warning.map(print_warning);

    if cli.check {
        println!("[*] Check finished successfully.");
    } else {
        println!("[*] Formatting finished successfully.");
    }

    Ok(())
}

async fn get_version_string(path: &str, args: &[&str]) -> Result<String, io::Error> {
    let version = Command::new(path)
        .args(args)
        .arg("--version")
        .output()
        .await?
        .stdout;
    Ok(from_utf8(&version).unwrap().replace('\n', ""))
}

#[allow(clippy::needless_pass_by_value)]
fn print_warning(warning: String) {
    println!("\n{} {}\n", "Warning:".yellow().bold(), warning);
}
