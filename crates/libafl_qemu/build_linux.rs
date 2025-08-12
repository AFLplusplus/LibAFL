use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use libafl_qemu_build::maybe_generate_stub_bindings;

static LIBAFL_QEMU_RUNTIME_TEST: &str = r#"
#include <stdio.h>
#include "libafl_qemu.h"

void __libafl_qemu_testfile() {}
"#;

pub fn build_libvharness(src_dir: &Path, arch: &str) -> (PathBuf, String) {
    let vharness_dir = src_dir.join("libvharness");
    let toolchains_dir = vharness_dir.join("toolchains");

    let toolchain_file = toolchains_dir.join(format!("{arch}-generic.cmake"));

    let api = if cfg!(feature = "nyx") {
        "nyx".to_string()
    } else {
        "lqemu".to_string()
    };

    let out = cmake::Config::new("libvharness")
        .define("CMAKE_TOOLCHAIN_FILE", &toolchain_file)
        .define("VHARNESS_API", &api)
        .define("VHARNESS_INCLUDE_ONLY", "ON")
        .define("VHARNESS_TESTS", "OFF")
        .build();

    (out.join("include/api.h"), api)
}

#[expect(clippy::too_many_lines)]
pub fn build() {
    // Note: Unique features are checked in libafl_qemu_sys
    println!(
        r#"cargo::rustc-check-cfg=cfg(cpu_target, values("arm", "aarch64", "hexagon", "i386", "mips", "ppc", "riscv32", "riscv64", "x86_64"))"#
    );

    let emulation_mode = if cfg!(feature = "usermode") {
        "usermode"
    } else if cfg!(feature = "systemmode") {
        "systemmode"
    } else {
        unreachable!(
            "The macros `assert_unique_feature` and `assert_at_least_one_feature` in \
            `libafl_qemu_sys/build_linux.rs` should panic before this code is reached."
        );
    };

    let src_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_dir = PathBuf::from(src_dir);

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(&out_dir);

    let mut target_dir = out_dir.clone();
    target_dir.pop();
    target_dir.pop();
    target_dir.pop();
    // let include_dir = target_dir.join("include");

    let stub_dir = src_dir.join("stubs");

    let qemu_asan_guest = cfg!(all(feature = "asan_guest", not(feature = "hexagon")));
    let qemu_asan_host = cfg!(all(feature = "asan_host", not(feature = "hexagon")));

    let libafl_runtime_testfile = out_dir.join("runtime_test.c");
    fs::write(&libafl_runtime_testfile, LIBAFL_QEMU_RUNTIME_TEST)
        .expect("Could not write runtime test file");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_linux.rs");
    // println!("cargo:rerun-if-changed={}", libafl_runtime_dir.display());

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
    } else if cfg!(feature = "riscv32") {
        "riscv32".to_string()
    } else if cfg!(feature = "riscv64") {
        "riscv64".to_string()
    } else if cfg!(feature = "hexagon") {
        "hexagon".to_string()
    } else {
        env::var("CPU_TARGET").unwrap_or_else(|_| "x86_64".to_string())
    };

    let (vharness_hdr, api) = build_libvharness(&src_dir, cpu_target.as_str());

    let vharness_bindings_file = out_dir.join(format!("{api}_bindings.rs"));
    let vharness_stub_bindings_file = stub_dir.join(format!("{api}_stub_bindings.rs"));

    if env::var("DOCS_RS").is_ok() || cfg!(feature = "clippy") {
        fs::copy(&vharness_stub_bindings_file, &vharness_bindings_file).unwrap_or_else(|_| panic!("Could not copy stub bindings file from {} to {}.",
                vharness_stub_bindings_file.display(),
                vharness_bindings_file.display()));
        return; // only build when we're not generating docs
    }

    println!("cargo:rerun-if-env-changed=CPU_TARGET");
    println!("cargo:rustc-cfg=cpu_target=\"{cpu_target}\"");
    println!(
        "cargo::rustc-check-cfg=cfg(cpu_target, values(\"x86_64\", \"arm\", \"aarch64\", \"i386\", \"mips\", \"ppc\", \"hexagon\", \"riscv32\", \"riscv64\"))"
    );

    let cross_cc = if cfg!(feature = "usermode") && (qemu_asan_guest || qemu_asan_host) {
        // TODO try to autodetect a cross compiler with the arch name (e.g. aarch64-linux-gnu-gcc)
        let cross_cc = env::var("CROSS_CC").unwrap_or_else(|_| {
            if cpu_target != env::consts::ARCH {
                println!("cargo:warning=CROSS_CC is not set, default to cc (things can go wrong since the selected cpu target ({cpu_target}) is different from the host arch ({}))", env::consts::ARCH);
            }
            "cc".to_owned()
        });
        println!("cargo:rerun-if-env-changed=CROSS_CC");

        cross_cc
    } else {
        String::new()
    };

    bindgen::Builder::default()
        .derive_debug(true)
        .derive_default(true)
        .impl_debug(true)
        .generate_comments(true)
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_global: true,
            is_bitfield: true,
        })
        // .rust_edition(bindgen::RustEdition::Edition2024)
        .header(vharness_hdr.display().to_string())
        .generate()
        .expect("Exit bindings generation failed.")
        .write_to_file(&vharness_bindings_file)
        .expect("Could not write bindings.");

    if !cfg!(feature = "nyx") {
        maybe_generate_stub_bindings(
            &cpu_target,
            emulation_mode,
            vharness_stub_bindings_file.as_path(),
            vharness_bindings_file.as_path(),
        );
    }

    let asan_rust = cfg!(feature = "asan_rust");

    if cfg!(feature = "usermode") && !asan_rust && (qemu_asan_guest || qemu_asan_host) {
        let qasan_dir = Path::new("libqasan");
        let qasan_dir = fs::canonicalize(qasan_dir).unwrap();
        println!("cargo:rerun-if-changed={}", qasan_dir.display());

        let mut make = Command::new("make");
        if cfg!(debug_assertions) {
            make.env("CFLAGS", "-DDEBUG=1");
        }
        assert!(
            make.current_dir(&out_dir)
                .env("CC", &cross_cc)
                .env("OUT_DIR", &target_dir)
                .arg("-C")
                .arg(&qasan_dir)
                .status()
                .expect("make failed")
                .success()
        );
    }

    if cfg!(feature = "usermode") && asan_rust {
        let asan_dir = Path::new("libafl_qemu_asan");
        let asan_dir = fs::canonicalize(asan_dir).unwrap();
        let just_file = asan_dir.join("Justfile");
        println!("cargo:rerun-if-changed={}", asan_dir.display());
        println!("cargo:rerun-if-changed={}", just_file.display());

        let asan_dir_str = asan_dir.to_str().unwrap();
        let just_file_str = just_file.to_str().unwrap();
        let target_dir_str = target_dir.to_str().unwrap();

        let profile = if cfg!(debug_assertions) {
            "dev"
        } else {
            "release"
        };

        let guest_args = [
            "just",
            "-d",
            asan_dir_str,
            "-f",
            just_file_str,
            "--set",
            "ARCH",
            &cpu_target,
            "--set",
            "PROFILE",
            profile,
            "--set",
            "TARGET_DIR",
            target_dir_str,
            "build_guest",
        ];
        just::run(guest_args.iter()).expect("Failed to build rust guest address sanitizer library");

        let host_args = [
            "just",
            "-d",
            asan_dir_str,
            "-f",
            just_file_str,
            "--set",
            "ARCH",
            &cpu_target,
            "--set",
            "PROFILE",
            profile,
            "--set",
            "TARGET_DIR",
            target_dir_str,
            "build_host",
        ];
        just::run(host_args.iter()).expect("Failed to build rust address sanitizer library");
    }
}
