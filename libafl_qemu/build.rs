use std::{env, fs, path::Path, process::Command};
use which::which;

const QEMU_URL: &str = "https://github.com/AFLplusplus/qemu-libafl-bridge";
const QEMU_DIRNAME: &str = "qemu-libafl-bridge";
const QEMU_REVISION: &str = "844841307dcbf390ecc6ea1f28d9c2cef25d3b0d";

fn build_dep_check(tools: &[&str]) {
    for tool in tools {
        which(tool).unwrap_or_else(|_| panic!("Build tool {} not found", tool));
    }
}

#[allow(clippy::too_many_lines)]
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CPU_TARGET");
    println!("cargo:rerun-if-env-changed=CROSS_CC");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if target_os != "linux" {
        return;
    }

    let jobs = env::var("CARGO_BUILD_JOBS");
    let cpu_target = env::var("CPU_TARGET").unwrap_or_else(|_| {
        println!("cargo:warning=CPU_TARGET is not set, default to x86_64");
        "x86_64".to_owned()
    });
    let cross_cc = env::var("CROSS_CC").unwrap_or_else(|_| {
        println!("cargo:warning=CROSS_CC is not set, default to cc (things can go wrong if CPU_TARGET is not the host arch)");
        "cc".to_owned()
    });

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
    //let cwd = env::current_dir().unwrap().to_string_lossy().to_string();

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
        Command::new("git")
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
            .unwrap();
        fs::write(&qemu_rev, QEMU_REVISION).unwrap();
    }

    let build_dir = qemu_path.join("build");
    let output_lib = build_dir.join(&format!("libqemu-{}.so", cpu_target));
    if !output_lib.is_file() {
        drop(
            Command::new("make")
                .current_dir(&qemu_path)
                .arg("distclean")
                .status(),
        );
        Command::new("./configure")
            .current_dir(&qemu_path)
            //.arg("--as-static-lib")
            .arg("--as-shared-lib")
            .arg(&format!("--target-list={}-linux-user", cpu_target))
            .args(&[
                "--audio-drv-list=",
                "--disable-blobs",
                "--disable-bochs",
                "--disable-brlapi",
                "--disable-bsd-user",
                "--disable-bzip2",
                "--disable-cap-ng",
                "--disable-cloop",
                "--disable-curl",
                "--disable-curses",
                "--disable-dmg",
                "--disable-fdt",
                "--disable-gcrypt",
                "--disable-glusterfs",
                "--disable-gnutls",
                "--disable-gtk",
                "--disable-guest-agent",
                "--disable-iconv",
                "--disable-libiscsi",
                "--disable-libnfs",
                "--disable-libssh",
                "--disable-libusb",
                "--disable-linux-aio",
                "--disable-live-block-migration",
                "--disable-lzo",
                "--disable-nettle",
                "--disable-numa",
                "--disable-opengl",
                "--disable-parallels",
                "--disable-plugins",
                "--disable-qcow1",
                "--disable-qed",
                "--disable-rbd",
                "--disable-rdma",
                "--disable-replication",
                "--disable-sdl",
                "--disable-seccomp",
                "--disable-smartcard",
                "--disable-snappy",
                "--disable-spice",
                "--disable-system",
                "--disable-tools",
                "--disable-tpm",
                "--disable-usb-redir",
                "--disable-vde",
                "--disable-vdi",
                "--disable-vhost-crypto",
                "--disable-vhost-kernel",
                "--disable-vhost-net",
                "--disable-vhost-scsi",
                "--disable-vhost-user",
                "--disable-vhost-vdpa",
                "--disable-vhost-vsock",
                "--disable-virglrenderer",
                "--disable-virtfs",
                "--disable-vnc",
                "--disable-vnc-jpeg",
                "--disable-vnc-png",
                "--disable-vnc-sasl",
                "--disable-vte",
                "--disable-vvfat",
                "--disable-xen",
                "--disable-xen-pci-passthrough",
                "--disable-xfsctl",
            ])
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

    #[cfg(feature = "python")]
    {
        let mut objects = vec![];
        for dir in &[
            build_dir.join("libcommon.fa.p"),
            build_dir.join(&format!("libqemu-{}-linux-user.fa.p", cpu_target)),
            //build_dir.join("libqemuutil.a.p"),
            //build_dir.join("libqom.fa.p"),
            //build_dir.join("libhwcore.fa.p"),
            //build_dir.join("libcapstone.a.p"),
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

        for obj in &objects {
            println!("cargo:rustc-cdylib-link-arg={}", obj.display());
        }

        println!("cargo:rustc-cdylib-link-arg=-Wl,--start-group");

        println!("cargo:rustc-cdylib-link-arg=-Wl,--whole-archive");
        println!(
            "cargo:rustc-cdylib-link-arg={}/libhwcore.fa",
            build_dir.display()
        );
        println!(
            "cargo:rustc-cdylib-link-arg={}/libqom.fa",
            build_dir.display()
        );
        println!("cargo:rustc-cdylib-link-arg=-Wl,--no-whole-archive");
        println!(
            "cargo:rustc-cdylib-link-arg={}/libcapstone.a",
            build_dir.display()
        );
        println!(
            "cargo:rustc-cdylib-link-arg={}/libqemuutil.a",
            build_dir.display()
        );
        println!(
            "cargo:rustc-cdylib-link-arg={}/libhwcore.fa",
            build_dir.display()
        );
        println!(
            "cargo:rustc-cdylib-link-arg={}/libqom.fa",
            build_dir.display()
        );

        println!("cargo:rustc-cdylib-link-arg=-lrt");
        println!("cargo:rustc-cdylib-link-arg=-lutil");
        println!("cargo:rustc-cdylib-link-arg=-lgthread-2.0");
        println!("cargo:rustc-cdylib-link-arg=-lglib-2.0");
        println!("cargo:rustc-cdylib-link-arg=-lstdc++");

        println!("cargo:rustc-cdylib-link-arg=-Wl,--end-group");
    }

    #[cfg(not(feature = "python"))]
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
    }

    println!("cargo:rerun-if-changed={}/libqasan.so", qasan_dir.display());
    drop(
        Command::new("make")
            .current_dir(&out_dir_path)
            .env("CC", cross_cc)
            .env("OUT_DIR", &target_dir)
            .arg("-C")
            .arg(&qasan_dir)
            .status(),
    );

    println!("cargo:rerun-if-changed=src/asan-giovese.c");
    println!("cargo:rerun-if-changed=src/asan-giovese.h");
    cc::Build::new()
        .warnings(false)
        .file(src_dir.join("asan-giovese.c"))
        .compile("asan_giovese");
}

/*
    // Build a static library
    let mut objects = vec![];
    for dir in &[
        build_dir.join("libcommon.fa.p"),
        build_dir.join(&format!("libqemu-{}-linux-user.fa.p", cpu_target)),
        build_dir.join("libqemuutil.a.p"),
        build_dir.join("libqom.fa.p"),
        build_dir.join("libhwcore.fa.p"),
        build_dir.join("libcapstone.a.p"),
    ] {
        for path in read_dir(dir).unwrap() {
            let path = path.unwrap().path();
            if path.is_file() {
                if let Some(name) = path.file_name() {
                    if name.to_string_lossy().starts_with("stubs") {
                        continue;
                    }
                    else if let Some(ext) = path.extension() {
                        if ext == "o" {
                            objects.push(path);
                        }
                    }
                }
            }
        }
    }


    Command::new("ar")
        .current_dir(&out_dir_path)
        .arg("crus")
        .arg("libqemu-bridge.a")
        .args(&objects)
        .status()
        .expect("Ar failed");

    println!("cargo:rustc-link-search=native={}", &out_dir);
    println!("cargo:rustc-link-lib=static=qemu-bridge");

    println!("cargo:rustc-link-lib=rt");
    println!("cargo:rustc-link-lib=util");
    println!("cargo:rustc-link-lib=gthread-2.0");
    println!("cargo:rustc-link-lib=glib-2.0");
    println!("cargo:rustc-link-lib=stdc++");

}
*/
