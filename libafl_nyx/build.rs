use std::process::Command;

fn main() {
    if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        println!("cargo:rerun-if-changed=build.rs");
        // let output = Command::new("./build_nyx_support.sh").output().expect("can't run ./build_nyx_support.sh");
        let status = Command::new("./build_nyx_support.sh")
            .status()
            .expect("can't run ./build_nyx_support.sh");
        if status.success() {
            println!("success to run ./build_nyx_support.sh");
        } else {
            panic!("fail to run ./build_nyx_support.sh");
        }
    } else {
        println!("cargo:warning=NYX node is only avaliable on x64 Linux");
    }
}
