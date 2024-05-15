use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use libafl_qemu_build::maybe_generate_stub_bindings;

#[allow(clippy::too_many_lines)]
pub fn build() {
    // Note: Unique features are checked in libafl_qemu_sys
    println!(r#"cargo::rustc-check-cfg=cfg(emulation_mode, values("usermode", "systemmode"))"#);
    println!(
        r#"cargo::rustc-check-cfg=cfg(cpu_target, values("arm", "aarch64", "hexagon", "i386", "mips", "ppc", "x86_64"))"#
    );

    let emulation_mode = if cfg!(feature = "usermode") {
        "usermode".to_string()
    } else if cfg!(feature = "systemmode") {
        "systemmode".to_string()
    } else {
        env::var("EMULATION_MODE").unwrap_or_else(|_| "usermode".to_string())
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

    let libafl_runtime_dir = src_dir.join("runtime");
    let libafl_qemu_hdr = libafl_runtime_dir.join(libafl_qemu_hdr_name);

    let runtime_bindings_file = out_dir.join("libafl_qemu_bindings.rs");
    let stub_runtime_bindings_file = src_dir.join("runtime/libafl_qemu_stub_bindings.rs");

    println!("cargo::rustc-check-cfg=cfg(emulation_mode, values(\"usermode\", \"systemmode\"))");
    println!("cargo:rustc-cfg=emulation_mode=\"{emulation_mode}\"");
    println!("cargo:rerun-if-env-changed=EMULATION_MODE");

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
    } else if cfg!(feature = "hexagon") {
        "hexagon".to_string()
    } else {
        env::var("CPU_TARGET").unwrap_or_else(|_| "x86_64".to_string())
    };
    println!("cargo:rerun-if-env-changed=CPU_TARGET");
    println!("cargo:rustc-cfg=cpu_target=\"{cpu_target}\"");
    println!("cargo::rustc-check-cfg=cfg(cpu_target, values(\"x86_64\", \"arm\", \"aarch64\", \"i386\", \"mips\", \"ppc\", \"hexagon\"))");

    let cross_cc = if (emulation_mode == "usermode") && (qemu_asan || qemu_asan_guest) {
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

    if env::var("DOCS_RS").is_ok() || cfg!(feature = "clippy") {
        fs::copy(&stub_runtime_bindings_file, &runtime_bindings_file)
            .expect("Could not copy stub bindings file");
        return; // only build when we're not generating docs
    }

    fs::create_dir_all(&include_dir).expect("Could not create include dir");

    fs::copy(
        libafl_qemu_hdr.clone(),
        include_dir.join(libafl_qemu_hdr_name),
    )
    .expect("Could not copy libafl_qemu.h to out directory.");

    bindgen::Builder::default()
        .derive_debug(true)
        .derive_default(true)
        .impl_debug(true)
        .generate_comments(true)
        .default_enum_style(bindgen::EnumVariation::NewType {
            is_global: true,
            is_bitfield: true,
        })
        .header(libafl_qemu_hdr.display().to_string())
        .generate()
        .expect("Exit bindings generation failed.")
        .write_to_file(&runtime_bindings_file)
        .expect("Could not write bindings.");

    maybe_generate_stub_bindings(
        &cpu_target,
        &emulation_mode,
        &stub_runtime_bindings_file,
        &runtime_bindings_file
    );

    if (emulation_mode == "usermode") && (qemu_asan || qemu_asan_guest) {
        let qasan_dir = Path::new("libqasan");
        let qasan_dir = fs::canonicalize(qasan_dir).unwrap();
        println!("cargo:rerun-if-changed={}", qasan_dir.display());

        let mut make = Command::new("make");
        if cfg!(debug_assertions) {
            make.env("CFLAGS", "-DDEBUG=1");
        }
        assert!(make
            .current_dir(&out_dir)
            .env("CC", &cross_cc)
            .env("OUT_DIR", &target_dir)
            .arg("-C")
            .arg(&qasan_dir)
            .status()
            .expect("make failed")
            .success());
    }
}
