use cmake::Config;
use std::env;
use std::path::Path;
use std::process::{exit, Command};


fn main(){
    
    // First we generate .cc and .h files from ffi.rs
    if !cfg!(windows) {
        println!("cargo:warning=No MacOS support yet.");
        exit(0);
    }

    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();
    let tinyinst = format!("{}/TinyInst", &cwd);

    println!("cargo:warning=Generating Bridge files.");

    // source
    Command::new("cxxbridge")
        .args(&["src/tinyinst.rs", "-o"])
        .arg(&format!("{}/bridge.cc", &tinyinst))
        .status()
        .unwrap();

    // header
    Command::new("cxxbridge")
        .args(&["src/tinyinst.rs", "--header", "-o"])
        .arg(&format!("{}/bridge.h", &tinyinst))
        .status()
        .unwrap();

    // shim
    std::fs::copy("./src/shim.cpp", "./tinyinst/shim.cpp").unwrap();
    
    std::fs::copy("./src/shim.h", "./tinyinst/shim.h").unwrap();

    let dst = Config::new("TinyInst")
        .generator("Visual Studio 17 2022") // make this configurable from env variable 
        .build_target("tinyinst")
        .profile("Release") // without this, it goes into RelWithDbInfo folder??
        .build();


    println!("cargo:warning={}",dst.display());
    println!("cargo:rustc-link-search={}\\build\\Release", dst.display()); // debug build?
    println!("cargo:rustc-link-search={}\\build\\third_party\\obj\\wkit\\lib", dst.display()); //xed

    println!("cargo:rustc-link-lib=static=tinyinst");
    println!("cargo:rustc-link-lib=static=xed");
    println!("cargo:rustc-link-lib=dylib=dbghelp");

    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=src/tinyinst.rs");
    println!("cargo:rerun-if-changed=build.rs");

}