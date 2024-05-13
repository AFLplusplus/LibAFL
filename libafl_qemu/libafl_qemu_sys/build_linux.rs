use std::{env, fs::copy, path::PathBuf};

use libafl_qemu_build::{build_with_bindings, maybe_generate_stub_bindings};

#[macro_export]
macro_rules! assert_unique_feature {
    () => {};
    ($first:tt $(,$rest:tt)*) => {
        $(
            #[cfg(all(not(any(docsrs, feature = "clippy")), feature = $first, feature = $rest))]
            compile_error!(concat!("features \"", $first, "\" and \"", $rest, "\" cannot be used together"));
        )*
        assert_unique_feature!($($rest),*);
    }
}

pub fn build() {
    println!(r#"cargo::rustc-check-cfg=cfg(emulation_mode, values("usermode", "systemmode"))"#);
    println!(
        r#"cargo::rustc-check-cfg=cfg(cpu_target, values("arm", "aarch64", "hexagon", "i386", "mips", "ppc", "x86_64"))"#
    );
    // Make sure that exactly one qemu mode is set
    assert_unique_feature!("usermode", "systemmode");
    let emulation_mode = if cfg!(feature = "usermode") {
        "usermode".to_string()
    } else if cfg!(feature = "systemmode") {
        "systemmode".to_string()
    } else {
        env::var("EMULATION_MODE").unwrap_or_else(|_| {
            println!(
                "cargo:warning=No emulation mode feature enabled or EMULATION_MODE env specified for libafl_qemu, supported: usermode, systemmmode - defaulting to usermode"
            );
            "usermode".to_string()
        })
    };
    println!("cargo::rustc-check-cfg=cfg(emulation_mode, values(\"usermode\", \"systemmode\"))");
    println!("cargo:rustc-cfg=emulation_mode=\"{emulation_mode}\"");
    println!("cargo:rerun-if-env-changed=EMULATION_MODE");

    // Make sure we have at most one architecutre feature set
    // Else, we default to `x86_64` - having a default makes CI easier :)
    assert_unique_feature!("arm", "aarch64", "i386", "x86_64", "mips", "ppc", "hexagon");

    // Make sure that we don't have BE set for any architecture other than arm and mips
    // Sure aarch64 may support BE, but its not in common usage and we don't
    // need it yet and so haven't tested it
    assert_unique_feature!("be", "aarch64", "i386", "x86_64", "hexagon");

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
            println!(
                "cargo:warning=No architecture feature enabled or CPU_TARGET env specified for libafl_qemu, supported: arm, aarch64, hexagon, i386, mips, ppc, x86_64 - defaulting to x86_64"
            );
            "x86_64".to_string()
        })
    };
    println!("cargo:rerun-if-env-changed=CPU_TARGET");
    println!("cargo:rustc-cfg=cpu_target=\"{cpu_target}\"");
    println!("cargo::rustc-check-cfg=cfg(cpu_target, values(\"x86_64\", \"arm\", \"aarch64\", \"i386\", \"mips\", \"ppc\", \"hexagon\"))");

    let jobs = env::var("NUM_JOBS")
        .ok()
        .map(|x| str::parse::<u32>(&x).expect("The number of jobs is not a valid integer!"));

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);
    let bindings_file = out_dir.join("bindings.rs");

    let src_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_dir = PathBuf::from(src_dir);
    let stub_bindings_file = src_dir.join("src/x86_64_stub_bindings.rs");

    if env::var("DOCS_RS").is_ok() || cfg!(feature = "clippy") {
        // Only build when we're not generating docs and not in clippy
        copy(stub_bindings_file, bindings_file).expect("Failed to copy the bindings stub");
        return;
    }

    build_with_bindings(
        &cpu_target,
        cfg!(feature = "be"),
        emulation_mode == "usermode",
        jobs,
        &bindings_file,
    );

    println!("cargo:rerun-if-changed={}", stub_bindings_file.display());

    // If the bindings are built and differ from the current stub, replace it with the freshly generated bindings
    maybe_generate_stub_bindings(
        &cpu_target,
        &emulation_mode,
        &stub_bindings_file,
        &bindings_file,
    );
}
