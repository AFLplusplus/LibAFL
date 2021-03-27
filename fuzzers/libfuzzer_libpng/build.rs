// build.rs

use std::{
    env,
    path::Path,
    process::{exit, Command},
};

use which::which;

const LIBPNG_URL: &str =
    "https://deac-fra.dl.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz";

fn build_dep_check(tools: &[&str]) {
    for tool in tools.into_iter() {
        println!("Checking for build tool {}...", tool);

        match which::which(tool) {
            Ok(path) => println!("Found build tool {}", path.to_str().unwrap()),
            Err(_) => {
                println!("ERROR: missing build tool {}", tool);
                exit(1);
            }
        };
    }
}

fn main() {
    if cfg!(windows) {
        println!("cargo:warning=Skipping libpng example on Windows");
        exit(0);
    }

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();
    let out_dir = out_dir.to_string_lossy().to_string();
    let out_dir_path = Path::new(&out_dir);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../libfuzzer_runtime/rt.c",);
    println!("cargo:rerun-if-changed=harness.cc");

    build_dep_check(&["clang", "clang++", "wget", "tar", "make"]);

    let libpng = format!("{}/libpng-1.6.37", &out_dir);
    let libpng_path = Path::new(&libpng);
    let libpng_tar = format!("{}/libpng-1.6.37.tar.xz", &cwd);

    // Enforce clang for its -fsanitize-coverage support.
    std::env::set_var("CC", "clang");
    std::env::set_var("CXX", "clang++");
    let ldflags = match env::var("LDFLAGS") {
        Ok(val) => val,
        Err(_) => "".to_string(),
    };

    if !libpng_path.is_dir() {
        if !Path::new(&libpng_tar).is_file() {
            println!("cargo:warning=Libpng not found, downloading...");
            // Download libpng
            Command::new("wget")
                .arg("-c")
                .arg(LIBPNG_URL)
                .arg("-O")
                .arg(&libpng_tar)
                .status()
                .unwrap();
        }
        Command::new("tar")
            .current_dir(&out_dir_path)
            .arg("-xvf")
            .arg(&libpng_tar)
            .status()
            .unwrap();
        Command::new(format!("{}/configure", &libpng))
            .current_dir(&libpng_path)
            .args(&[
                "--disable-shared",
                &format!("--host={}", env::var("TARGET").unwrap())[..],
            ])
            .env("CC", "clang")
            .env("CXX", "clang++")
            .env(
                "CFLAGS",
                "-O3 -g -D_DEFAULT_SOURCE -fPIE -fsanitize-coverage=trace-pc-guard",
            )
            .env(
                "CXXFLAGS",
                "-O3 -g -D_DEFAULT_SOURCE -fPIE -fsanitize-coverage=trace-pc-guard",
            )
            .env(
                "LDFLAGS",
                format!("-g -fPIE -fsanitize-coverage=trace-pc-guard {}", ldflags),
            )
            .status()
            .unwrap();
        Command::new("make")
            .current_dir(&libpng_path)
            .status()
            .unwrap();
    }

    cc::Build::new()
        .file("../libfuzzer_runtime/rt.c")
        .compile("libfuzzer-sys");

    cc::Build::new()
        .include(&libpng_path)
        .cpp(true)
        .flag("-fsanitize-coverage=trace-pc-guard")
        // .define("HAS_DUMMY_CRASH", "1")
        .file("./harness.cc")
        .compile("libfuzzer-harness");

    println!("cargo:rustc-link-search=native={}", &out_dir);
    println!("cargo:rustc-link-search=native={}/.libs", &libpng);
    println!("cargo:rustc-link-lib=static=png16");

    //Deps for libpng: -pthread -lz -lm
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=z");

    //For the C++ harness
    //must by dylib for android
    println!("cargo:rustc-link-lib=dylib=stdc++");
}
