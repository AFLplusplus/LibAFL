use std::{env, fs, path::Path, process::Command};
use which::which;

const QEMU_URL: &str = "https://github.com/AFLplusplus/qemu-libafl-bridge";
const QEMU_DIRNAME: &str = "qemu-libafl-bridge";
const QEMU_REVISION: &str = "6a9a929222cbc8b10adfb048aa24f73486e0a886";

fn build_dep_check(tools: &[&str]) {
    for tool in tools {
        which(tool).unwrap_or_else(|_| panic!("Build tool {} not found", tool));
    }
}

#[macro_export]
macro_rules! assert_unique_feature {
    () => {};
    ($first:tt $(,$rest:tt)*) => {
        $(
            #[cfg(not(feature = "clippy"))] // ignore multiple definition for clippy
            #[cfg(all(feature = $first, feature = $rest))]
            compile_error!(concat!("features \"", $first, "\" and \"", $rest, "\" cannot be used together"));
        )*
        assert_unique_feature!($($rest),*);
    }
}

#[allow(clippy::too_many_lines)]
pub fn build() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/asan-giovese.c");
    println!("cargo:rerun-if-changed=src/asan-giovese.h");
    println!("cargo:rerun-if-env-changed=CROSS_CC");

    // Make sure we have at most one architecutre feature set
    // Else, we default to `x86_64` - having a default makes CI easier :)
    assert_unique_feature!("arm", "aarch64", "i386", "i86_64");

    let cpu_target = if cfg!(feature = "x86_64") {
        "x86_64".to_string()
    } else if cfg!(feature = "arm") {
        "arm".to_string()
    } else if cfg!(feature = "aarch64") {
        "aarch64".to_string()
    } else if cfg!(feature = "i386") {
        "i386".to_string()
    } else {
        env::var("CPU_TARGET").unwrap_or_else(|_| {
            println!(
                "cargo:warning=No architecture feature enabled or CPU_TARGET env specified for libafl_qemu, supported: arm, aarch64, i386, x86_64 - defaulting to x86_64"
            );
            "x86_64".to_string()
        })
    };

    let jobs = env::var("NUM_JOBS");

    let cross_cc = env::var("CROSS_CC").unwrap_or_else(|_| {
        println!("cargo:warning=CROSS_CC is not set, default to cc (things can go wrong if the selected cpu target ({}) is not the host arch ({}))", cpu_target, env::consts::ARCH);
        "cc".to_owned()
    });

    println!("cargo:rustc-cfg=cpu_target=\"{}\"", cpu_target);

    if std::env::var("DOCS_RS").is_ok() {
        return; // only build when we're not generating docs
    }

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    let out_dir_path = Path::new(&out_dir);
    let mut target_dir = out_dir_path.to_path_buf();
    target_dir.pop();
    target_dir.pop();
    target_dir.pop();
    let qasan_dir = Path::new("libqasan");
    let qasan_dir = fs::canonicalize(&qasan_dir).unwrap();
    let src_dir = Path::new("src");

    println!("cargo:rerun-if-changed=libqasan");

    build_dep_check(&["git", "make"]);

    let qemu_rev = out_dir_path.join("QEMU_REVISION");
    let qemu_path = out_dir_path.join(QEMU_DIRNAME);

    if qemu_rev.exists()
        && fs::read_to_string(&qemu_rev).expect("Failed to read QEMU_REVISION") != QEMU_REVISION
    {
        drop(fs::remove_dir_all(&qemu_path));
    }

    if !qemu_path.is_dir() {
        println!(
            "cargo:warning=Qemu not found, cloning with git ({})...",
            QEMU_REVISION
        );
        fs::create_dir_all(&qemu_path).unwrap();
        Command::new("git")
            .current_dir(&qemu_path)
            .arg("init")
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(&qemu_path)
            .arg("remote")
            .arg("add")
            .arg("origin")
            .arg(QEMU_URL)
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(&qemu_path)
            .arg("fetch")
            .arg("--depth")
            .arg("1")
            .arg("origin")
            .arg(QEMU_REVISION)
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(&qemu_path)
            .arg("checkout")
            .arg("FETCH_HEAD")
            .status()
            .unwrap();
        /*Command::new("git")
            .current_dir(&out_dir_path)
            .arg("clone")
            .arg(QEMU_URL)
            .status()
            .unwrap();
        Command::new("git")
            .current_dir(&qemu_path)
            .arg("checkout")
            .arg(QEMU_REVISION)
            .status()
            .unwrap();*/
        fs::write(&qemu_rev, QEMU_REVISION).unwrap();
    }

    let build_dir = qemu_path.join("build");
    let output_lib = build_dir.join(&format!("libqemu-{}.so", cpu_target));
    if !output_lib.is_file() {
        /*drop(
            Command::new("make")
                .current_dir(&qemu_path)
                .arg("distclean")
                .status(),
        );*/
        Command::new("./configure")
            .current_dir(&qemu_path)
            //.arg("--as-static-lib")
            .arg("--as-shared-lib")
            .arg(&format!("--target-list={}-linux-user", cpu_target))
            .args(&["--disable-blobs", "--disable-bsd-user", "--disable-fdt"])
            .status()
            .expect("Configure failed");
        if let Ok(j) = jobs {
            Command::new("make")
                .current_dir(&qemu_path)
                .arg("-j")
                .arg(&j)
                .status()
                .expect("Make failed");
        } else {
            Command::new("make")
                .current_dir(&qemu_path)
                .arg("-j")
                .status()
                .expect("Make failed");
        }
        //let _ = remove_file(build_dir.join(&format!("libqemu-{}.so", cpu_target)));
    }

    let mut objects = vec![];
    for dir in &[
        build_dir.join("libcommon.fa.p"),
        build_dir.join(&format!("libqemu-{}-linux-user.fa.p", cpu_target)),
        //build_dir.join("libcommon-user.fa.p"),
        //build_dir.join("libqemuutil.a.p"),
        //build_dir.join("libqom.fa.p"),
        //build_dir.join("libhwcore.fa.p"),
    ] {
        for path in fs::read_dir(dir).unwrap() {
            let path = path.unwrap().path();
            if path.is_file() {
                if let Some(name) = path.file_name() {
                    if name.to_string_lossy().starts_with("stubs") {
                        continue;
                    } else if let Some(ext) = path.extension() {
                        if ext == "o" {
                            objects.push(path);
                        }
                    }
                }
            }
        }
    }

    Command::new("ld")
        .current_dir(&out_dir_path)
        .arg("-o")
        .arg("libqemu-partially-linked.o")
        .arg("-r")
        .args(objects)
        .arg("--start-group")
        .arg("--whole-archive")
        .arg(format!("{}/libhwcore.fa", build_dir.display()))
        .arg(format!("{}/libqom.fa", build_dir.display()))
        .arg(format!("{}/libevent-loop-base.a", build_dir.display()))
        .arg("--no-whole-archive")
        .arg(format!("{}/libqemuutil.a", build_dir.display()))
        .arg(format!("{}/libhwcore.fa", build_dir.display()))
        .arg(format!("{}/libqom.fa", build_dir.display()))
        .arg(format!(
            "--dynamic-list={}/plugins/qemu-plugins.symbols",
            qemu_path.display()
        ))
        .status()
        .expect("Partial linked failure");

    drop(
        Command::new("ar")
            .current_dir(&out_dir_path)
            .arg("crus")
            .arg("libqemu-partially-linked.a")
            .arg("libqemu-partially-linked.o")
            .status(),
    );

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=qemu-partially-linked");

    println!("cargo:rustc-link-lib=rt");
    println!("cargo:rustc-link-lib=gmodule-2.0");
    println!("cargo:rustc-link-lib=glib-2.0");
    println!("cargo:rustc-link-lib=stdc++");

    /* #[cfg(not(feature = "python"))]
    {
        fs::copy(
            build_dir.join(&format!("libqemu-{}.so", cpu_target)),
            target_dir.join(&format!("libqemu-{}.so", cpu_target)),
        )
        .expect("Failed to copy the QEMU shared object");

        println!(
            "cargo:rustc-link-search=native={}",
            &target_dir.to_string_lossy().to_string()
        );
        println!("cargo:rustc-link-lib=qemu-{}", cpu_target);

        println!("cargo:rustc-env=LD_LIBRARY_PATH={}", target_dir.display());
    } */

    drop(
        Command::new("make")
            .current_dir(&out_dir_path)
            .env("CC", &cross_cc)
            .env("OUT_DIR", &target_dir)
            .arg("-C")
            .arg(&qasan_dir)
            .arg("clean")
            .status(),
    );
    drop(
        Command::new("make")
            .current_dir(&out_dir_path)
            .env("CC", &cross_cc)
            .env("OUT_DIR", &target_dir)
            .arg("-C")
            .arg(&qasan_dir)
            .status(),
    );

    cc::Build::new()
        .warnings(false)
        .file(src_dir.join("asan-giovese.c"))
        .compile("asan_giovese");
}
