use std::{env, path::PathBuf, process::Command};
fn main() {
    if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") && !cfg!(doc) {
        // Use CARGO_TARGET_DIR if available, otherwise fall back to OUT_DIR's parent directories
        let target_dir = if let Ok(target_dir) = env::var("CARGO_TARGET_DIR") {
            PathBuf::from(target_dir)
        } else {
            // OUT_DIR is usually $TARGET/{debug|release}/build/$PKG-$HASH/out
            // We want $TARGET/{debug|release}
            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
            out_dir
                .ancestors()
                .nth(3) // This is still a fallback, but at least we try CARGO_TARGET_DIR first
                .map(|p| p.to_path_buf())
                .expect("Failed to determine target directory from OUT_DIR")
        };
        println!("cargo:rerun-if-changed=build.rs");
        // let output = Command::new("./build_nyx_support.sh").output().expect("can't run ./build_nyx_support.sh");
        let status = Command::new("./build_nyx_support.sh")
            .arg(target_dir)
            .status()
            .expect("can't run ./build_nyx_support.sh");
        if status.success() {
            println!("success to run ./build_nyx_support.sh");
        } else {
            panic!("fail to run ./build_nyx_support.sh");
        }
    } else {
        println!("cargo:warning=NYX node is only available on x64 Linux");
    }
}
