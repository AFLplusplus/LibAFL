use std::{env, fs, path::Path, process::Command};
use which::which;

const QEMU_URL: &str = "https://github.com/AFLplusplus/qemu-libafl-bridge";
const QEMU_DIRNAME: &str = "qemu-libafl-bridge";
const QEMU_REVISION: &str = "35d36bf8fa2d483965a57ee0c7d7a997e8798273";

fn build_dep_check(tools: &[&str]) {
    for tool in tools {
        which(tool).unwrap_or_else(|_| panic!("Build tool {tool} not found"));
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
    #[cfg(feature = "usermode")]
    println!("cargo:rerun-if-env-changed=CROSS_CC");

    // Make sure we have at most one architecutre feature set
    // Else, we default to `x86_64` - having a default makes CI easier :)
    assert_unique_feature!("arm", "aarch64", "i386", "i86_64");

    // Make sure that we don't have BE set for any architecture other than arm
    // Sure aarch64 may support BE, but its not in common usage and we don't
    // need it yet and so haven't tested it
    assert_unique_feature!("be", "aarch64", "i386", "i86_64");

    let mut cpu_target = if cfg!(feature = "x86_64") {
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

    #[cfg(feature = "usermode")]
    let cross_cc = env::var("CROSS_CC").unwrap_or_else(|_| {
        println!("cargo:warning=CROSS_CC is not set, default to cc (things can go wrong if the selected cpu target ({cpu_target}) is not the host arch ({}))", env::consts::ARCH);
        "cc".to_owned()
    });

    println!("cargo:rustc-cfg=cpu_target=\"{cpu_target}\"");

    // qemu-system-arm supports both big and little endian configurations and so
    // therefore the "be" feature should ignored in this configuration. Also
    // ignore the feature if we are running in clippy which enables all the
    // features at once (disabling the check for mutually exclusive options)
    // resulting in cpu_target being set to 'x86_64' above which obviously
    // doesn't support BE.
    if cfg!(feature = "be") && cfg!(feature = "arm") && cfg!(feature = "usermode") && !cfg!(feature = "clippy"){
        // We have told rustc which CPU target to use above (it doesn't need
        // to make any changes for endianness), however, we need QEMU to be
        // built for the right endian-ness, so we update the cpu_target for
        // here on down
        cpu_target += "eb";
    }

    if std::env::var("DOCS_RS").is_ok() {
        return; // only build when we're not generating docs
    }

    let custum_qemu_dir = env::var_os("CUSTOM_QEMU_DIR").map(|x| x.to_string_lossy().to_string());
    let custum_qemu_no_build = env::var("CUSTOM_QEMU_NO_BUILD").is_ok();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    let out_dir_path = Path::new(&out_dir);
    let mut target_dir = out_dir_path.to_path_buf();
    target_dir.pop();
    target_dir.pop();
    target_dir.pop();

    println!("cargo:rerun-if-changed=libqasan");

    build_dep_check(&["git", "make"]);

    let qemu_path = if let Some(qemu_dir) = custum_qemu_dir.as_ref() {
        Path::new(&qemu_dir).to_path_buf()
    } else {
        let qemu_path = target_dir.join(QEMU_DIRNAME);

        let qemu_rev = target_dir.join("QEMU_REVISION");
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
            fs::write(&qemu_rev, QEMU_REVISION).unwrap();
        }

        qemu_path
    };

    #[cfg(feature = "usermode")]
    let target_suffix = "linux-user";
    #[cfg(not(feature = "usermode"))]
    let target_suffix = "softmmu";

    let build_dir = out_dir_path.join("build");
    if !build_dir.is_dir() {
        fs::create_dir_all(&build_dir).unwrap();
    }

    #[cfg(feature = "usermode")]
    let output_lib = build_dir.join(&format!("libqemu-{cpu_target}.so"));
    #[cfg(not(feature = "usermode"))]
    let output_lib = build_dir.join(&format!("libqemu-system-{}.so", cpu_target));

    println!("cargo:rerun-if-changed={}", output_lib.to_string_lossy());

    if !output_lib.is_file() || (custum_qemu_dir.is_some() && !custum_qemu_no_build) {
        /*drop(
            Command::new("make")
                .current_dir(&qemu_path)
                .arg("distclean")
                .status(),
        );*/
        let configure = qemu_path.join("configure");

        #[cfg(feature = "usermode")]
        Command::new(configure)
            .current_dir(&build_dir)
            //.arg("--as-static-lib")
            .arg("--as-shared-lib")
            .arg(&format!("--target-list={cpu_target}-{target_suffix}"))
            .args(["--disable-blobs", "--disable-bsd-user", "--disable-fdt"])
            .status()
            .expect("Configure failed");
        #[cfg(not(feature = "usermode"))]
        Command::new(configure)
            .current_dir(&build_dir)
            //.arg("--as-static-lib")
            .arg("--as-shared-lib")
            .arg(&format!("--target-list={}-{}", cpu_target, target_suffix))
            .status()
            .expect("Configure failed");
        if let Ok(j) = jobs {
            Command::new("make")
                .current_dir(&build_dir)
                .arg("-j")
                .arg(&j)
                .status()
                .expect("Make failed");
        } else {
            Command::new("make")
                .current_dir(&build_dir)
                .arg("-j")
                .status()
                .expect("Make failed");
        }
    }

    let mut objects = vec![];
    for dir in &[
        build_dir.join("libcommon.fa.p"),
        build_dir.join(&format!("libqemu-{cpu_target}-{target_suffix}.fa.p")),
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

    #[cfg(feature = "usermode")]
    Command::new("ld")
        .current_dir(out_dir_path)
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

    #[cfg(not(feature = "usermode"))]
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
        .arg(format!("{}/libio.fa", build_dir.display()))
        .arg(format!("{}/libcrypto.fa", build_dir.display()))
        .arg(format!("{}/libauthz.fa", build_dir.display()))
        .arg(format!("{}/libblockdev.fa", build_dir.display()))
        .arg(format!("{}/libblock.fa", build_dir.display()))
        .arg(format!("{}/libchardev.fa", build_dir.display()))
        .arg(format!("{}/libqmp.fa", build_dir.display()))
        .arg("--no-whole-archive")
        .arg(format!("{}/libqemuutil.a", build_dir.display()))
        .arg(format!(
            "{}/subprojects/libvhost-user/libvhost-user-glib.a",
            build_dir.display()
        ))
        .arg(format!(
            "{}/subprojects/libvhost-user/libvhost-user.a",
            build_dir.display()
        ))
        .arg(format!(
            "{}/subprojects/libvduse/libvduse.a",
            build_dir.display()
        ))
        .arg(format!("{}/libfdt.a", build_dir.display()))
        .arg(format!("{}/libslirp.a", build_dir.display()))
        .arg(format!("{}/libmigration.fa", build_dir.display()))
        .arg(format!("{}/libhwcore.fa", build_dir.display()))
        .arg(format!("{}/libqom.fa", build_dir.display()))
        .arg(format!("{}/libio.fa", build_dir.display()))
        .arg(format!("{}/libcrypto.fa", build_dir.display()))
        .arg(format!("{}/libauthz.fa", build_dir.display()))
        .arg(format!("{}/libblockdev.fa", build_dir.display()))
        .arg(format!("{}/libblock.fa", build_dir.display()))
        .arg(format!("{}/libchardev.fa", build_dir.display()))
        .arg(format!("{}/libqmp.fa", build_dir.display()))
        .arg(format!(
            "--dynamic-list={}/plugins/qemu-plugins.symbols",
            qemu_path.display()
        ))
        .status()
        .expect("Partial linked failure");

    Command::new("ar")
        .current_dir(out_dir_path)
        .arg("crus")
        .arg("libqemu-partially-linked.a")
        .arg("libqemu-partially-linked.o")
        .status()
        .expect("Ar creation");

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=qemu-partially-linked");

    #[cfg(not(feature = "usermode"))]
    {
        println!("cargo:rustc-link-lib=png");
        println!("cargo:rustc-link-lib=z");
        println!("cargo:rustc-link-lib=gio-2.0");
        println!("cargo:rustc-link-lib=gobject-2.0");
        println!("cargo:rustc-link-lib=ncursesw");
        println!("cargo:rustc-link-lib=tinfo");
        println!("cargo:rustc-link-lib=gtk-3");
        println!("cargo:rustc-link-lib=gdk-3");
        println!("cargo:rustc-link-lib=pangocairo-1.0");
        println!("cargo:rustc-link-lib=pango-1.0");
        println!("cargo:rustc-link-lib=harfbuzz");
        println!("cargo:rustc-link-lib=atk-1.0");
        println!("cargo:rustc-link-lib=cairo-gobject");
        println!("cargo:rustc-link-lib=cairo");
        println!("cargo:rustc-link-lib=gdk_pixbuf-2.0");
        println!("cargo:rustc-link-lib=X11");
        println!("cargo:rustc-link-lib=epoxy");
        println!("cargo:rustc-link-lib=pixman-1");

        fs::create_dir_all(target_dir.join("pc-bios")).unwrap();
        for path in fs::read_dir(build_dir.join("pc-bios")).unwrap() {
            let path = path.unwrap().path();
            if path.is_file() {
                if let Some(name) = path.file_name() {
                    fs::copy(&path, target_dir.join("pc-bios").join(name))
                        .expect("Failed to copy a pc-bios folder file");
                }
            }
        }
    }

    println!("cargo:rustc-link-lib=rt");
    println!("cargo:rustc-link-lib=gmodule-2.0");
    println!("cargo:rustc-link-lib=glib-2.0");
    println!("cargo:rustc-link-lib=stdc++");

    println!("cargo:rustc-link-lib=z");

    /* #[cfg(not(feature = "python"))]
    {
        fs::copy(
            build_dir.join(&format!("libqemu-{}.so", cpu_target)),
            target_dir.join(&format!("libqemu-{}.so", cpu_target)),
        )
        .expect("Failed to copy the QEMU shared object");

        println!(
            "cargo:rustc-link-search=native={}",
            &target_dir.to_string_lossy()
        );
        println!("cargo:rustc-link-lib=qemu-{}", cpu_target);

        println!("cargo:rustc-env=LD_LIBRARY_PATH={}", target_dir.display());
    } */

    #[cfg(feature = "usermode")]
    {
        let qasan_dir = Path::new("libqasan");
        let qasan_dir = fs::canonicalize(qasan_dir).unwrap();
        let src_dir = Path::new("src");

        assert!(Command::new("make")
            .current_dir(out_dir_path)
            .env("CC", &cross_cc)
            .env("OUT_DIR", &target_dir)
            .arg("-C")
            .arg(&qasan_dir)
            .arg("clean")
            .status()
            .expect("make failed")
            .success());
        assert!(Command::new("make")
            .current_dir(out_dir_path)
            .env("CC", &cross_cc)
            .env("OUT_DIR", &target_dir)
            .arg("-C")
            .arg(&qasan_dir)
            .status()
            .expect("make failed")
            .success());
    }
}
