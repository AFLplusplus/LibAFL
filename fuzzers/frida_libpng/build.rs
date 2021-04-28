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

        match which(tool) {
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
        println!("cargo:warning=Skipping libpng frida example on Windows");
        exit(0);
    }

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let cwd = env::current_dir().unwrap().to_string_lossy().to_string();
    let out_dir = out_dir.to_string_lossy().to_string();
    let out_dir_path = Path::new(&out_dir);
    std::fs::create_dir_all(&out_dir).expect(&format!("Failed to create {}", &out_dir));

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../libfuzzer_runtime/rt.c",);
    println!("cargo:rerun-if-changed=harness.cc");

    build_dep_check(&["clang", "clang++", "wget", "tar", "make"]);

    let libpng = format!("{}/libpng-1.6.37", &out_dir);
    let libpng_path = Path::new(&libpng);
    let libpng_tar = format!("{}/libpng-1.6.37.tar.xz", &cwd);

    // Enforce clang for its -fsanitize-coverage support.
    let clang = match env::var("CLANG_PATH") {
        Ok(path) => path,
        Err(_) => "clang".to_string(),
    };
    let clangpp = format!("{}++", &clang);
    std::env::set_var("CC", &clang);
    std::env::set_var("CXX", &clangpp);
    let ldflags = match env::var("LDFLAGS") {
        Ok(val) => val,
        Err(_) => "".to_string(),
    };

    // println!("cargo:warning=output path is {}", libpng);
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
            .arg("xvf")
            .arg(&libpng_tar)
            .status()
            .unwrap();
        Command::new(format!("{}/configure", &libpng))
            .current_dir(&libpng_path)
            .args(&[
                "--disable-shared",
                &format!("--host={}", env::var("TARGET").unwrap())[..],
            ])
            .env("CC", &clang)
            .env("CXX", &clangpp)
            .env(
                "CFLAGS",
                "-O3 -g -D_DEFAULT_SOURCE -fPIC -fno-omit-frame-pointer",
            )
            .env(
                "CXXFLAGS",
                "-O3 -g -D_DEFAULT_SOURCE -fPIC -fno-omit-frame-pointer",
            )
            .env(
                "LDFLAGS",
                //format!("-g -fPIE -fsanitize=address {}", ldflags),
                format!("-g -fPIE {}", ldflags),
            )
            .status()
            .unwrap();
        Command::new("make")
            .current_dir(&libpng_path)
            .status()
            .unwrap();
    }

    let status = cc::Build::new()
        .cpp(true)
        .get_compiler()
        .to_command()
        .current_dir(&cwd)
        .arg("-I")
        .arg(&libpng)
        //.arg("-D")
        //.arg("HAS_DUMMY_CRASH=1")
        .arg("-fPIC")
        .arg("-shared")
        .arg("-O3")
        //.arg("-fomit-frame-pointer")
        .arg(if env::var("CARGO_CFG_TARGET_OS").unwrap() == "android" {
            "-static-libstdc++"
        } else {
            ""
        })
        .arg("-o")
        .arg(format!("{}/libpng-harness.so", &out_dir))
        .arg("./harness.cc")
        .arg(format!("{}/.libs/libpng16.a", &libpng))
        .arg("-l")
        .arg("z")
        .status()
        .unwrap();
    assert!(status.success());
}
