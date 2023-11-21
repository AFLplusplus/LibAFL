use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

#[cfg(feature = "rabbit")]
const NAMESPACE: &str = "🐇";
#[cfg(not(feature = "rabbit"))]
const NAMESPACE: &str = "__libafl";
const NAMESPACE_LEN: usize = NAMESPACE.as_bytes().len();

#[allow(clippy::too_many_lines)]
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
        let nm = "nm"; // NOTE: we use system nm here because llvm-nm doesn't respect the encoding?

        let redefined_symbols = custom_lib_dir.join("redefs.txt");

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

        let mut child = Command::new(nm)
            .arg(&objfile_orig)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        let mut redefinitions_file = BufWriter::new(File::create(&redefined_symbols).unwrap());

        let replacement = format!("_ZN{NAMESPACE_LEN}{NAMESPACE}");

        // redefine all the rust-mangled symbols we can
        // TODO this will break when v0 mangling is stabilised
        for line in BufReader::new(child.stdout.take().unwrap()).lines() {
            let line = line.unwrap();
            let (_, symbol) = line.rsplit_once(' ').unwrap();
            if symbol.starts_with("_ZN") {
                writeln!(
                    redefinitions_file,
                    "{} {}",
                    symbol,
                    symbol.replacen("_ZN", &replacement, 1)
                )
                .unwrap();
            }
        }
        redefinitions_file.flush().unwrap();
        drop(redefinitions_file);

        assert!(
            !child.wait().map(|s| !s.success()).unwrap_or(true),
            "Couldn't link runtime crate! Do you have the llvm-tools component installed?"
        );

        let mut command = Command::new(rust_objcopy);

        for symbol in [
            "__rust_drop_panic",
            "__rust_foreign_exception",
            "rust_begin_unwind",
            "rust_panic",
            "rust_eh_personality",
            "__rg_oom",
            "__rdl_oom",
            "__rdl_alloc",
            "__rust_alloc",
            "__rdl_dealloc",
            "__rust_dealloc",
            "__rdl_realloc",
            "__rust_realloc",
            "__rdl_alloc_zeroed",
            "__rust_alloc_zeroed",
            "__rust_alloc_error_handler",
            "__rust_no_alloc_shim_is_unstable",
            "__rust_alloc_error_handler_should_panic",
        ] {
            command
                .arg("--redefine-sym")
                .arg(format!("{symbol}={symbol}_libafl_libfuzzer_runtime"));
        }

        command
            .arg("--redefine-syms")
            .arg(redefined_symbols)
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
