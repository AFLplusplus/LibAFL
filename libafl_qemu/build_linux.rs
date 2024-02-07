use std::{env, fs, path::Path, process::Command};

pub fn build() {
    // Note: Unique features are checked in libafl_qemu_sys

    let emulation_mode = if cfg!(feature = "usermode") {
        "usermode".to_string()
    } else if cfg!(feature = "systemmode") {
        "systemmode".to_string()
    } else {
        env::var("EMULATION_MODE").unwrap_or_else(|_| {
            "usermode".to_string()
        })
    };

    let build_libqasan = cfg!(all(feature = "build_libqasan", not(feature = "hexagon")));

    println!("cargo:rustc-cfg=emulation_mode=\"{emulation_mode}\"");
    println!("cargo:rerun-if-env-changed=EMULATION_MODE");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_linux.rs");

    let cpu_target = if cfg!(feature = "x86_64") {
        "x86_64".to_string()
    } else if cfg!(feature = "arm") {
        "arm".to_string()
    } else if cfg!(feature = "aarch64") {
        "aarch64".to_string()
    } else if cfg!(feature = "i386") {
        "i386".to_string()
    } else if cfg!(feature = "mips") {
        "mips".to_string()
    } else if cfg!(feature = "ppc") {
        "ppc".to_string()
    } else if cfg!(feature = "hexagon") {
        "hexagon".to_string()
    } else {
        env::var("CPU_TARGET").unwrap_or_else(|_| {
            "x86_64".to_string()
        })
    };
    println!("cargo:rerun-if-env-changed=CPU_TARGET");
    println!("cargo:rustc-cfg=cpu_target=\"{cpu_target}\"");

    let cross_cc = if (emulation_mode == "usermode") && build_libqasan {
        // TODO try to autodetect a cross compiler with the arch name (e.g. aarch64-linux-gnu-gcc)
        let cross_cc = env::var("CROSS_CC").unwrap_or_else(|_| {
            println!("cargo:warning=CROSS_CC is not set, default to cc (things can go wrong if the selected cpu target ({cpu_target}) is not the host arch ({}))", env::consts::ARCH);
            "cc".to_owned()
        });
        println!("cargo:rerun-if-env-changed=CROSS_CC");

        cross_cc
    } else {
        String::new()
    };

    if std::env::var("DOCS_RS").is_ok() {
        return; // only build when we're not generating docs
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir_path = Path::new(&out_dir);
    let mut target_dir = out_dir_path.to_path_buf();
    target_dir.pop();
    target_dir.pop();
    target_dir.pop();

    if (emulation_mode == "usermode") && build_libqasan {
        let qasan_dir = Path::new("libqasan");
        let qasan_dir = fs::canonicalize(qasan_dir).unwrap();
        println!("cargo:rerun-if-changed={}", qasan_dir.display());

        let mut make = Command::new("make");
        if cfg!(debug_assertions) {
            make.env("CFLAGS", "-DDEBUG=1");
        }
        assert!(make
            .current_dir(out_dir_path)
            .env("CC", &cross_cc)
            .env("OUT_DIR", &target_dir)
            .arg("-C")
            .arg(&qasan_dir)
            .status()
            .expect("make failed")
            .success());
        // println!("cargo:rerun-if-changed={}/libqasan.so", target_dir.display());
    }
}
