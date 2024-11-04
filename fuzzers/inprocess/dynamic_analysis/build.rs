use std::{env, process::Command};

fn main() {
    let current_dir = env::current_dir().unwrap();
    let lcms_dir = current_dir.join("Little-CMS");
    if !lcms_dir.exists() {
        println!("cargo:warning=Downloading Little-CMS");
        // Clone the Little-CMS repository if the directory doesn't exist
        let status = Command::new("git")
            .args(&[
                "clone",
                "https://github.com/mm2/Little-CMS",
                lcms_dir.to_str().unwrap(),
            ])
            .status()
            .expect("Failed to clone Little-CMS repository");

        if !status.success() {
            panic!("Failed to clone Little-CMS repository");
        }
    }

    // Tell Cargo that if the given file changes, to rerun this build script
    println!("cargo:rerun-if-changed=build.rs");
}
