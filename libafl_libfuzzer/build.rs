use std::{path::PathBuf, process::Command};

fn main() {
    if cfg!(any(feature = "cargo-clippy", docsrs)) {
        return; // skip when clippy or docs is running
    }
    assert!(
        cfg!(target_os = "linux"),
        "The libafl_libfuzzer runtime may only be built for linux; failing fast."
    );

    println!("cargo:rerun-if-changed=libafl_libfuzzer_runtime/src");
    println!("cargo:rerun-if-changed=libafl_libfuzzer_runtime/Cargo.toml");
    println!("cargo:rerun-if-changed=libafl_libfuzzer_runtime/build.rs");

    let custom_lib_dir =
        PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("libafl_libfuzzer");
    std::fs::create_dir_all(&custom_lib_dir)
        .expect("Couldn't create the output directory for the fuzzer runtime build");

    let mut lib_src = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    lib_src.push("libafl_libfuzzer_runtime");

    let mut command = Command::new(std::env::var_os("CARGO").unwrap());
    command
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS");

    for (var, _) in std::env::vars() {
        if var.starts_with("CARGO_PKG_") || var.starts_with("CARGO_FEATURE_") {
            command.env_remove(var);
        }
    }

    command
        .env("PATH", std::env::var_os("PATH").unwrap())
        .current_dir(&lib_src);

    let _ = std::fs::rename(lib_src.join("Cargo.toml.orig"), lib_src.join("Cargo.toml"));

    command.arg("build");

    let mut features = vec![];

    if cfg!(any(feature = "fork")) {
        features.push("fork");
    }
    if cfg!(any(feature = "introspection")) {
        features.push("libafl/introspection");
    }

    if features.is_empty() {
        command.arg("--features").arg(features.join(","));
    }

    command
        .arg("--release")
        .arg("--no-default-features")
        .arg("--target-dir")
        .arg(&custom_lib_dir)
        .arg("--target")
        .arg(std::env::var_os("TARGET").unwrap());

    assert!(
        !command.status().map(|s| !s.success()).unwrap_or(true),
        "Couldn't build runtime crate! Did you remember to use nightly?"
    );

    let mut lib_path = custom_lib_dir.join(std::env::var_os("TARGET").unwrap());
    lib_path.push("release");

    if cfg!(target_family = "unix") {
        use std::path::Path;

        lib_path.push("libafl_libfuzzer_runtime.a");
        let target_libdir = Command::new("rustc")
            .args(["--print", "target-libdir"])
            .output()
            .expect("Couldn't find rustc's target-libdir");
        let target_libdir = String::from_utf8(target_libdir.stdout).unwrap();
        let target_libdir = Path::new(target_libdir.trim());

        let rust_lld = target_libdir.join("../bin/rust-lld");
        let rust_ar = target_libdir.join("../bin/llvm-ar"); // NOTE: depends on llvm-tools
        let rust_objcopy = target_libdir.join("../bin/llvm-objcopy"); // NOTE: depends on llvm-tools

        let objfile_orig = custom_lib_dir.join("libFuzzer.o");
        let objfile_dest = custom_lib_dir.join("libFuzzer-mimalloc.o");

        let mut command = Command::new(rust_lld);
        command
            .args(["-flavor", "gnu"])
            .arg("-r")
            .arg("--whole-archive")
            .arg(lib_path)
            .args(["-o", objfile_orig.to_str().expect("Invalid path characters present in your current directory prevent us from linking to the runtime")]);

        assert!(
            !command.status().map(|s| !s.success()).unwrap_or(true),
            "Couldn't link runtime crate! Do you have the llvm-tools component installed?"
        );

        let mut command = Command::new(rust_objcopy);
        command
            .args(["--redefine-sym", "__rust_alloc=__rust_alloc_mimalloc"])
            .args(["--redefine-sym", "__rust_dealloc=__rust_dealloc_mimalloc"])
            .args(["--redefine-sym", "__rust_realloc=__rust_realloc_mimalloc"])
            .args([
                "--redefine-sym",
                "__rust_alloc_zeroed=__rust_alloc_zeroed_mimalloc",
            ])
            .args([
                "--redefine-sym",
                "__rust_alloc_error_handler=__rust_alloc_error_handler_mimalloc",
            ])
            .args([
                "--redefine-sym",
                "__rust_no_alloc_shim_is_unstable=__rust_no_alloc_shim_is_unstable_mimalloc",
            ])
            .args([
                "--redefine-sym",
                "__rust_alloc_error_handler_should_panic=__rust_alloc_error_handler_should_panic_mimalloc",
            ])
            .args([&objfile_orig, &objfile_dest]);

        assert!(
            !command.status().map(|s| !s.success()).unwrap_or(true),
            "Couldn't rename allocators in the runtime crate! Do you have the llvm-tools component installed?"
        );

        let mut command = Command::new(rust_ar);
        command
            .arg("cr")
            .arg(custom_lib_dir.join("libFuzzer.a"))
            .arg(objfile_dest);

        assert!(
            !command.status().map(|s| !s.success()).unwrap_or(true),
            "Couldn't create runtime archive!"
        );

        #[cfg(feature = "embed-runtime")]
        {
            // NOTE: lib, .a are added always on unix-like systems as described in:
            // https://gist.github.com/novafacing/1389cbb2f0a362d7eb103e67b4468e2b
            println!(
                "cargo:rustc-env=LIBAFL_LIBFUZZER_RUNTIME_PATH={}",
                custom_lib_dir.join("libFuzzer.a").display()
            );
        }

        println!(
            "cargo:rustc-link-search=native={}",
            custom_lib_dir.to_str().unwrap()
        );
        println!("cargo:rustc-link-lib=static=Fuzzer");
    } else {
        println!(
            "cargo:rustc-link-search=native={}",
            lib_path.to_str().unwrap()
        );
        println!("cargo:rustc-link-lib=static=afl_fuzzer_runtime");
    }

    println!("cargo:rustc-link-lib=stdc++");
}
