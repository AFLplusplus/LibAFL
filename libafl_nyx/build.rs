use std::process::Command;


#[cfg(target_os = "linux")]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // let output = Command::new("./build_nyx_support.sh").output().expect("can't run ./build_nyx_support.sh");
	let status = Command::new("./build_nyx_support.sh").status().expect("can't run ./build_nyx_support.sh");
	if status.success(){
		println!("success to run ./build_nyx_support.sh");
	}else{
		panic!("fail to run ./build_nyx_support.sh");
	}
	
}

#[cfg(not(target_os = "linux"))]
fn main(){
    panic("NYX node is only avaliable on Linux");
}
