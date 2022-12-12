use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    process::{Command, Stdio},
};

use walkdir::WalkDir;

pub fn run_git_diff(args: &[&str]) -> String {
    let output = Command::new("git")
        .stdout(Stdio::piped())
        .arg("diff")
        .args(args)
        .output()
        .expect("git diff failed");

    String::from_utf8(output.stdout).unwrap()
}

pub fn get_diffing_files(commit_name: &str) -> Vec<PathBuf> {
    let args = vec!["--name-only", commit_name];
    let diff = run_git_diff(&args);
    diff.lines()
        .map(|x| PathBuf::from(x))
        .filter(|x| x.is_file())
        .collect()
}

pub fn get_diffing_crates(diffing_files: &[PathBuf]) -> HashSet<PathBuf> {
    let mut crates = HashSet::default();
    for file in diffing_files {
        if let Some(dir) = file.parent() {
            if dir.join("Cargo.toml").is_file() {
                crates.insert(dir.join("Cargo.toml"));
            }
        }
    }
    crates
}

pub fn find_all_crates() -> HashSet<PathBuf> {
    let mut crates = HashSet::default();
    for entry in WalkDir::new(".")
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| !e.file_type().is_dir())
    {
        let file_name = String::from(entry.file_name().to_string_lossy());
        if file_name == "Cargo.toml" {
            crates.insert(entry.into_path());
        }
    }
    crates
}

pub fn extend_diffing_crates_with_deps(
    diffing_crates: &mut HashSet<PathBuf>,
    all_crates: &HashSet<PathBuf>,
) {
    let mut crate_names = HashMap::<String, PathBuf>::new();
    for file in all_crates {
        let manifest = cargo_toml::Manifest::from_path(file).expect("cannot read manifest");
        if let Some(package) = manifest.package {
            crate_names.insert(package.name, file.clone());
        }
    }

    let not_diffing = all_crates.difference(diffing_crates);
    let mut deps_map = HashMap::<String, HashSet<_>>::new();

    for file in not_diffing {
        let manifest = cargo_toml::Manifest::from_path(file).expect("cannot read manifest");
        if let Some(package) = manifest.package {
            for (dep, _) in manifest.dependencies {
                deps_map
                    .entry(dep)
                    .or_insert(HashSet::default())
                    .insert(package.name.clone());
            }
        }
    }

    let diffing_crates_orig = diffing_crates.clone();
    for file in diffing_crates_orig {
        let manifest = cargo_toml::Manifest::from_path(file).expect("cannot read manifest");
        if let Some(package) = manifest.package {
            if let Some(names) = deps_map.get(&package.name) {
                for name in names {
                    if let Some(path) = crate_names.get(name) {
                        diffing_crates.insert(path.clone());
                    }
                }
            }
        }
    }
}
