use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // let output = Command::new("./build_nyx_support.sh").output().expect("can't run ./build_nyx_support.sh");
	let status = Command::new("./build_nyx_support.sh").status().expect("can't run ./build_nyx_support.sh");
	if status.success(){
		panic!("success to run ./build_nyx_support.sh");
	}else{
		panic!("fail to run ./build_nyx_support.sh");
	}
	
}