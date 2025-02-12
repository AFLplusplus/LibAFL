use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    path::{Component, PathBuf},
    process::{Command, Stdio},
};

use walkdir::WalkDir;

#[must_use]
pub fn run_git_diff(args: &[&str]) -> String {
    let output = Command::new("git")
        .stdout(Stdio::piped())
        .arg("diff")
        .args(args)
        .output()
        .expect("git diff failed");

    String::from_utf8(output.stdout).unwrap()
}

#[must_use]
pub fn get_diffing_files(commits: &[String]) -> HashSet<PathBuf> {
    let mut files = HashSet::<PathBuf>::default();
    for commit_name in commits {
        let args = vec!["--name-only", commit_name];
        for file in run_git_diff(&args)
            .lines()
            .map(PathBuf::from)
            .filter(|x| x.is_file())
        {
            files.insert(file);
        }
    }
    files
}

#[expect(clippy::implicit_hasher)]
#[must_use]
pub fn get_diffing_crates(diffing_files: &HashSet<PathBuf>) -> HashSet<PathBuf> {
    // TODO maybe consider using a combination of this and https://docs.rs/cargo/0.28.0/cargo/sources/path/struct.PathSource.html
    let mut crates = HashSet::default();
    for file in diffing_files {
        if let Some(dir) = file.parent() {
            let manifest = dir.join("Cargo.toml");
            if manifest.is_file()
                && cargo_toml::Manifest::from_path(&manifest)
                    .expect("cannot read manifest")
                    .package
                    .is_some()
            {
                crates.insert(manifest);
            } else if let Some(dir1) = dir.parent() {
                let manifest = dir1.join("Cargo.toml");
                if manifest.is_file()
                    && cargo_toml::Manifest::from_path(&manifest)
                        .expect("cannot read manifest")
                        .package
                        .is_some()
                {
                    crates.insert(manifest);
                } else if let Some(dir2) = dir1.parent() {
                    let manifest = dir2.join("Cargo.toml");
                    if manifest.is_file()
                        && cargo_toml::Manifest::from_path(&manifest)
                            .expect("cannot read manifest")
                            .package
                            .is_some()
                    {
                        crates.insert(manifest);
                    }
                }
            }
        }
    }
    crates
}

#[must_use]
pub fn find_all_crates() -> HashSet<PathBuf> {
    let mut crates = HashSet::default();
    for entry in WalkDir::new(".")
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            !e.file_type().is_dir()
                && e.path()
                    .components()
                    .filter(|c| *c == Component::Normal(OsStr::new("target")))
                    .count()
                    == 0
        })
    {
        let file_name = String::from(entry.file_name().to_string_lossy());
        if file_name == "Cargo.toml" {
            crates.insert(entry.into_path());
        }
    }
    crates
}

#[expect(clippy::implicit_hasher)]
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
