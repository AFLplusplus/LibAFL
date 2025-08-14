use std::{env, fs, path::PathBuf, process::Command};

const LIBVHARNESS_URL: &str = "https://github.com/rmalmain/libvharness.git";
const LIBVHARNESS_DIRNAME: &str = "libvharness";
const LIBVHARNESS_COMMIT: &str = "9516e58dfb05d4547b829b9efb0d3ad7e0f849f6";

fn main() {
    let src_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_dir = PathBuf::from(src_dir).join("src");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    let out_dir = PathBuf::from(&out_dir);

    let mut target_dir = out_dir.clone();
    target_dir.pop();
    target_dir.pop();
    target_dir.pop();

    let vharness_dir = target_dir.join(LIBVHARNESS_DIRNAME);
    let toolchains_dir = vharness_dir.join("toolchains");
    let vharness_stub = src_dir.join("stub.rs");

    let gen_binding = out_dir.join("bindings.rs");

    let api = if cfg!(feature = "nyx") {
        "nyx".to_string()
    } else {
        "lqemu".to_string()
    };

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

    let toolchain_file = toolchains_dir.join(format!("{cpu_target}-generic.cmake"));

    let vharness_rev = vharness_dir.join("QEMU_REVISION");
    if !vharness_rev.exists()
        || fs::read_to_string(&vharness_rev).expect("Failed to read QEMU_REVISION") != LIBVHARNESS_COMMIT
    {
        drop(fs::remove_dir_all(&vharness_dir));
    }

    if !vharness_dir.exists() {
        fs::create_dir_all(&vharness_dir).unwrap();
        assert!(
            Command::new("git")
                .current_dir(&vharness_dir)
                .arg("init")
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .current_dir(&vharness_dir)
                .arg("remote")
                .arg("add")
                .arg("origin")
                .arg(LIBVHARNESS_URL)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .current_dir(&vharness_dir)
                .arg("fetch")
                .arg("--depth")
                .arg("1")
                .arg("origin")
                .arg(LIBVHARNESS_COMMIT)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("git")
                .current_dir(&vharness_dir)
                .arg("checkout")
                .arg("FETCH_HEAD")
                .status()
                .unwrap()
                .success()
        );

        fs::write(&vharness_rev, LIBVHARNESS_COMMIT).unwrap();
    }

    let vharness_out_dir = cmake::Config::new(&vharness_dir)
        .define("CMAKE_TOOLCHAIN_FILE", &toolchain_file)
        .define("VHARNESS_API", &api)
        .define("VHARNESS_TESTS", "OFF")
        .build();

    let vharness_include_dir = vharness_out_dir.join("include");

    if cfg!(feature = "static") && cfg!(feature = "shared") {
        panic!("Both static and dynamic features are set.");
    }

    let link_kind = if cfg!(feature = "shared") {
        "dylib"
    } else {
        // fall back to static linking.
        "static"
    };

    println!("cargo:rerun-if-env-changed=LIBVHARNESS_GEN_STUBS");
    println!(
        "cargo:rustc-link-search={}/build",
        vharness_out_dir.display()
    );
    println!("cargo:rustc-link-lib={link_kind}=vharness");

    if env::var("DOCS_RS").is_ok() || cfg!(feature = "clippy") {
        fs::copy(vharness_stub, gen_binding).unwrap();
    } else {
        bindgen::Builder::default()
            .header(format!("{}/api.h", vharness_include_dir.display()))
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .clang_arg(format!("-I{}", vharness_include_dir.display()))
            .derive_debug(true)
            .derive_default(true)
            .impl_debug(true)
            .generate_comments(true)
            .default_enum_style(bindgen::EnumVariation::NewType {
                is_global: true,
                is_bitfield: true,
            })
            // .rust_edition(bindgen::RustEdition::Edition2024)
            .generate()
            .expect("Exit bindings generation failed.")
            .write_to_file(&gen_binding)
            .expect("Could not write libvharness bindings.");

        if env::var("LIBVHARNESS_GEN_STUBS").is_ok() && cpu_target == "x86_64" && api == "lqemu" {
            fs::copy(gen_binding, vharness_stub).unwrap();
        }
    }
}
