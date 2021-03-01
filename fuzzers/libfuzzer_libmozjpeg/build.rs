// build.rs

use std::env;
use std::path::Path;
use std::process::Command;

const LIBMOZJPEG_URL: &str = "https://github.com/mozilla/mozjpeg/archive/v4.0.3.tar.gz";

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();
    let out_dir = out_dir.to_string_lossy().to_string();
    let out_dir_path = Path::new(&out_dir);

    println!("cargo:rerun-if-changed=./runtime/rt.c",);
    println!("cargo:rerun-if-changed=harness.cc");

    let libmozjpeg = format!("{}/mozjpeg-4.0.3", &out_dir);
    let libmozjpeg_path = Path::new(&libmozjpeg);
    let libmozjpeg_tar = format!("{}/v4.0.3.tar.gz", &cwd);

    // Enforce clang for its -fsanitize-coverage support.
    std::env::set_var("CC", "clang");
    std::env::set_var("CXX", "clang++");

    if !libmozjpeg_path.is_dir() {
        if !Path::new(&libmozjpeg_tar).is_file() {
            println!("cargo:warning=Libmozjpeg not found, downloading...");
            // Download libmozjpeg
            Command::new("wget")
                .arg("-c")
                .arg(LIBMOZJPEG_URL)
                .arg("-O")
                .arg(&libmozjpeg_tar)
                .status()
                .unwrap();
        }
        Command::new("tar")
            .current_dir(&out_dir_path)
            .arg("-xvf")
            .arg(&libmozjpeg_tar)
            .status()
            .unwrap();
        Command::new(format!("{}/cmake", &libmozjpeg))
            .current_dir(&out_dir_path)
            .args(&[
                "-G\"Unix Makefiles\"",
                "--disable-shared",
                &libmozjpeg,
                "CC=clang",
                "CFLAGS=-O3 -g -D_DEFAULT_SOURCE -fPIE -fsanitize-coverage=trace-pc-guard",
                "LDFLAGS=-g -fPIE -fsanitize-coverage=trace-pc-guard",
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
            .env("LDFLAGS", "-g -fPIE -fsanitize-coverage=trace-pc-guard");
        Command::new("make")
            .current_dir(&libmozjpeg_path)
            //.arg(&format!("-j{}", num_cpus::get()))
            .args(&[
                "CC=clang",
                "CXX=clang++",
                "CFLAGS=-O3 -g -D_DEFAULT_SOURCE -fPIE -fsanitize-coverage=trace-pc-guard",
                "LDFLAGS=-g -fPIE -fsanitize-coverage=trace-pc-guard",
                "CXXFLAGS=-D_DEFAULT_SOURCE -fPIE -fsanitize-coverage=trace-pc-guard",
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
            .env("LDFLAGS", "-g -fPIE -fsanitize-coverage=trace-pc-guard")
            .status()
            .unwrap();
    }

    cc::Build::new()
        .file("../libfuzzer_runtime/rt.c")
        .compile("libfuzzer-sys");

    cc::Build::new()
        .include(&libmozjpeg_path)
        .flag("-fsanitize-coverage=trace-pc-guard")
        .file("./harness.cc")
        .compile("libfuzzer-harness");

    println!("cargo:rustc-link-search=native={}", &out_dir);
    println!("cargo:rustc-link-search=native={}/", &libmozjpeg);
    println!("cargo:rustc-link-lib=static=jpeg");

    //Deps for libmozjpeg: -pthread -lz -lm
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=z");

    //For the C++ harness
    println!("cargo:rustc-link-lib=static=stdc++");

    println!("cargo:rerun-if-changed=build.rs");
}
