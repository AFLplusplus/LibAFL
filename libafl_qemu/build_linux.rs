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
    let include_dir = target_dir.join("include");

    let qemu_asan_guest = cfg!(all(feature = "build_libgasan", not(feature = "hexagon")));
    let qemu_asan = cfg!(all(feature = "build_libqasan", not(feature = "hexagon")));

    let libafl_qemu_hdr_name = "libafl_qemu.h";
    let libafl_qemu_arch_hdr_name = "libafl_qemu_arch.h";
    let libafl_qemu_defs_hdr_name = "libafl_qemu_defs.h";
    let libafl_qemu_impl_hdr_name = "libafl_qemu_impl.h";

    let nyx_hdr_name = "nyx_api.h";

    let libafl_runtime_dir = src_dir.join("runtime");

    let libafl_qemu_hdr = libafl_runtime_dir.join(libafl_qemu_hdr_name);
    let libafl_qemu_arch_hdr = libafl_runtime_dir.join(libafl_qemu_arch_hdr_name);
    let libafl_qemu_defs_hdr = libafl_runtime_dir.join(libafl_qemu_defs_hdr_name);
    let libafl_qemu_impl_hdr = libafl_runtime_dir.join(libafl_qemu_impl_hdr_name);

    let nyx_hdr = libafl_runtime_dir.join(nyx_hdr_name);

    let libafl_runtime_testfile = out_dir.join("runtime_test.c");
    fs::write(&libafl_runtime_testfile, LIBAFL_QEMU_RUNTIME_TEST)
        .expect("Could not write runtime test file");

    let mut runtime_test_cc_compiler = cc::Build::new();

    runtime_test_cc_compiler
        .cpp(false)
        .include(&libafl_runtime_dir)
        .file(&libafl_runtime_testfile);

    runtime_test_cc_compiler
        .try_compile("runtime_test")
        .unwrap();

    let runtime_bindings_file = out_dir.join("libafl_qemu_bindings.rs");
    let stub_runtime_bindings_file = src_dir.join("runtime/libafl_qemu_stub_bindings.rs");

    let nyx_bindings_file = out_dir.join("nyx_bindings.rs");
    let stub_nyx_bindings_file = src_dir.join("runtime/nyx_stub_bindings.rs");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_linux.rs");
    println!("cargo:rerun-if-changed={}", libafl_runtime_dir.display());

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
    println!("cargo:rerun-if-env-changed=CPU_TARGET");
    println!("cargo:rustc-cfg=cpu_target=\"{cpu_target}\"");
    println!(
        "cargo::rustc-check-cfg=cfg(cpu_target, values(\"x86_64\", \"arm\", \"aarch64\", \"i386\", \"mips\", \"ppc\", \"hexagon\", \"riscv32\", \"riscv64\"))"
    );

    let cross_cc = if cfg!(feature = "usermode") && (qemu_asan || qemu_asan_guest) {
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

    if env::var("DOCS_RS").is_ok() || cfg!(feature = "clippy") {
        fs::copy(&stub_runtime_bindings_file, &runtime_bindings_file)
            .expect("Could not copy stub bindings file");
        fs::copy(&stub_nyx_bindings_file, &nyx_bindings_file)
            .expect("Could not copy stub bindings file");
        return; // only build when we're not generating docs
    }

    fs::create_dir_all(&include_dir).expect("Could not create include dir");

    fs::copy(
        libafl_qemu_hdr.clone(),
        include_dir.join(libafl_qemu_hdr_name),
    )
    .expect("Could not copy libafl_qemu.h to out directory.");

    fs::copy(
        libafl_qemu_arch_hdr.clone(),
        include_dir.join(libafl_qemu_arch_hdr_name),
    )
    .expect("Could not copy libafl_qemu_arch.h to out directory.");

    fs::copy(
        libafl_qemu_defs_hdr.clone(),
        include_dir.join(libafl_qemu_defs_hdr_name),
    )
    .expect("Could not copy libafl_qemu_defs.h to out directory.");

    fs::copy(
        libafl_qemu_impl_hdr.clone(),
        include_dir.join(libafl_qemu_impl_hdr_name),
    )
    .expect("Could not copy libafl_qemu_impl.h to out directory.");

    fs::copy(nyx_hdr.clone(), include_dir.join(nyx_hdr_name))
        .expect("Could not copy libafl_qemu_impl.h to out directory.");

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
        .header(libafl_qemu_hdr.display().to_string())
        .generate()
        .expect("Exit bindings generation failed.")
        .write_to_file(&runtime_bindings_file)
        .expect("Could not write bindings.");

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
        .header(nyx_hdr.display().to_string())
        .generate()
        .expect("Exit bindings generation failed.")
        .write_to_file(&nyx_bindings_file)
        .expect("Could not write bindings.");

    maybe_generate_stub_bindings(
        &cpu_target,
        emulation_mode,
        stub_runtime_bindings_file.as_path(),
        runtime_bindings_file.as_path(),
    );

    maybe_generate_stub_bindings(
        &cpu_target,
        emulation_mode,
        stub_nyx_bindings_file.as_path(),
        nyx_bindings_file.as_path(),
    );

    if cfg!(feature = "usermode") && (qemu_asan || qemu_asan_guest) {
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
}
