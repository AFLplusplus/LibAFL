use std::{env, fs, path::PathBuf, process::Command};

const LIBVHARNESS_URL: &str = "https://github.com/rmalmain/libvharness.git";
const LIBVHARNESS_DIRNAME: &str = "libvharness";
const LIBVHARNESS_COMMIT: &str = "9a316966ce7aa4bd9f733491511e6ac4be6dd980";

fn main() {
    let runs_in_docs_rs = env::var("DOCS_RS").is_ok();

    let is_linux = env::var("CARGO_CFG_TARGET_OS").unwrap() == "linux";

    let src_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let src_dir = PathBuf::from(src_dir).join("src");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    let out_dir = PathBuf::from(&out_dir);

    let mut target_dir = out_dir.clone();
    target_dir.pop();
    target_dir.pop();
    target_dir.pop();

    let gen_binding = out_dir.join("bindings.rs");
    let vharness_stub = src_dir.join("stub.rs");

    if runs_in_docs_rs || cfg!(feature = "clippy") || !is_linux {
        println!("cargo:warning=libvharness_sys only builds for Linux targets");
        fs::copy(vharness_stub, gen_binding).unwrap();
    } else {
        println!("cargo:rerun-if-env-changed=LIBVHARNESS_GEN_STUBS");
        println!("cargo:rerun-if-env-changed=VHARNESS_DIR");

        let vharness_dir = if let Some(vharness_dir) = env::var_os("VHARNESS_DIR") {
            println!("cargo:rerun-if-env-changed={}", vharness_dir.display());
            PathBuf::from(&vharness_dir)
        } else {
            let vharness_dir = target_dir.join(LIBVHARNESS_DIRNAME);

            let vharness_rev = vharness_dir.join("QEMU_REVISION");
            if !vharness_rev.exists()
                || fs::read_to_string(&vharness_rev).expect("Failed to read QEMU_REVISION")
                    != LIBVHARNESS_COMMIT
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

            vharness_dir
        };

        let vharness_out_dir = target_dir.join("vharness_out");
        let toolchains_dir = vharness_dir.join("toolchains");

        let api = if cfg!(feature = "nyx") {
            "nyx".to_string()
        } else {
            "lqemu".to_string()
        };

        let platform = if cfg!(feature = "linux") {
            "linux".to_string()
        } else if cfg!(feature = "linux-kernel") {
            "linux-kernel".to_string()
        } else {
            "generic".to_string()
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

        let toolchain_file = toolchains_dir.join(format!("{cpu_target}-{platform}.cmake"));

        if !toolchain_file.exists() {
            println!("Unsupported toolchain: target CPU {cpu_target} - platform {platform}");
        }

        if vharness_out_dir.exists() {
            fs::remove_dir_all(&vharness_out_dir).unwrap();
        }

        // target vharness compilation
        cmake::Config::new(&vharness_dir)
            .define("CMAKE_TOOLCHAIN_FILE", &toolchain_file)
            .define("VHARNESS_API", &api)
            .define("VHARNESS_TESTS", "OFF")
            .define("VHARNESS_INCLUDE_ONLY", "ON")
            .out_dir(&vharness_out_dir)
            .build();

        // host vharness_compilation
        let vharness_out_dir = cmake::Config::new(&vharness_dir)
            .define(
                "CMAKE_TOOLCHAIN_FILE",
                toolchains_dir.join(format!("{cpu_target}-generic.cmake")),
            )
            .define("VHARNESS_API", &api)
            .define("VHARNESS_TESTS", "OFF")
            .define("VHARNESS_INCLUDE_ONLY", "ON")
            .build();

        let vharness_include_dir = vharness_out_dir.join("include");

        bindgen::Builder::default()
            .header(format!("{}/{api}.h", vharness_include_dir.display()))
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
