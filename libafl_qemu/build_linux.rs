use std::{env, fs, path::Path, process::Command};

use which::which;

const QEMU_URL: &str = "https://github.com/AFLplusplus/qemu-libafl-bridge";
const QEMU_DIRNAME: &str = "qemu-libafl-bridge";
const QEMU_REVISION: &str = "f26a5ca6137bb5d4d0dcfe5451fb16d4c0551c4e";

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
    println!("cargo:rustc-cfg=emulation_mode=\"{emulation_mode}\"");
    println!("cargo:rerun-if-env-changed=EMULATION_MODE");

    println!("cargo:rerun-if-changed=build.rs");

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
    println!("cargo:rerun-if-env-changed=CPU_TARGET");

    let jobs = env::var("NUM_JOBS");

    let cross_cc = if emulation_mode == "usermode" {
        let cross_cc = env::var("CROSS_CC").unwrap_or_else(|_| {
            println!("cargo:warning=CROSS_CC is not set, default to cc (things can go wrong if the selected cpu target ({cpu_target}) is not the host arch ({}))", env::consts::ARCH);
            "cc".to_owned()
        });
        println!("cargo:rerun-if-env-changed=CROSS_CC");

        cross_cc
    } else {
        String::new()
    };

    println!("cargo:rustc-cfg=cpu_target=\"{cpu_target}\"");

    // qemu-system-arm supports both big and little endian configurations and so
    // therefore the "be" feature should ignored in this configuration. Also
    // ignore the feature if we are running in clippy which enables all the
    // features at once (disabling the check for mutually exclusive options)
    // resulting in cpu_target being set to 'x86_64' above which obviously
    // doesn't support BE.
    if cfg!(feature = "be")
        && cfg!(feature = "arm")
        && cfg!(feature = "usermode")
        && !cfg!(feature = "clippy")
    {
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
    println!("cargo:rerun-if-env-changed=CUSTOM_QEMU_DIR");
    println!("cargo:rerun-if-env-changed=CUSTOM_QEMU_NO_BUILD");

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

    let build_dir = qemu_path.join("build");

    let target_suffix = if emulation_mode == "usermode" {
        "linux-user".to_string()
    } else {
        "softmmu".to_string()
    };

    let output_lib = if emulation_mode == "usermode" {
        build_dir.join(format!("libqemu-{cpu_target}.so"))
    } else {
        build_dir.join(format!("libqemu-system-{cpu_target}.so"))
    };

    println!("cargo:rerun-if-changed={}", output_lib.to_string_lossy());

    if !output_lib.is_file() || (custum_qemu_dir.is_some() && !custum_qemu_no_build) {
        /*drop(
            Command::new("make")
                .current_dir(&qemu_path)
                .arg("distclean")
                .status(),
        );*/
        if emulation_mode == "usermode" {
            Command::new("./configure")
                .current_dir(&qemu_path)
                //.arg("--as-static-lib")
                .arg("--as-shared-lib")
                .arg(&format!("--target-list={cpu_target}-{target_suffix}"))
                .args([
                    "--disable-blobs",
                    "--disable-bsd-user",
                    "--disable-fdt",
                    "--disable-system",
                ])
                .status()
                .expect("Configure failed");
        } else {
            Command::new("./configure")
                .current_dir(&qemu_path)
                //.arg("--as-static-lib")
                .arg("--as-shared-lib")
                .arg(&format!("--target-list={cpu_target}-{target_suffix}"))
                .arg(if cfg!(feature = "slirp") {
                    "--enable-slirp"
                } else {
                    "--disable-slirp"
                })
                .arg("--enable-fdt=internal")
                .arg("--audio-drv-list=")
                .arg("--disable-alsa")
                .arg("--disable-attr")
                .arg("--disable-auth-pam")
                .arg("--disable-dbus-display")
                .arg("--disable-blobs")
                .arg("--disable-bochs")
                .arg("--disable-bpf")
                .arg("--disable-brlapi")
                .arg("--disable-bsd-user")
                .arg("--disable-bzip2")
                .arg("--disable-cap-ng")
                .arg("--disable-canokey")
                .arg("--disable-cloop")
                .arg("--disable-cocoa")
                .arg("--disable-coreaudio")
                .arg("--disable-curl")
                .arg("--disable-curses")
                .arg("--disable-dmg")
                .arg("--disable-docs")
                .arg("--disable-dsound")
                .arg("--disable-fuse")
                .arg("--disable-fuse-lseek")
                .arg("--disable-gcrypt")
                .arg("--disable-gettext")
                .arg("--disable-gio")
                .arg("--disable-glusterfs")
                .arg("--disable-gnutls")
                .arg("--disable-gtk")
                .arg("--disable-guest-agent")
                .arg("--disable-guest-agent-msi")
                .arg("--disable-hax")
                .arg("--disable-hvf")
                .arg("--disable-iconv")
                .arg("--disable-jack")
                .arg("--disable-keyring")
                .arg("--disable-kvm")
                .arg("--disable-libdaxctl")
                .arg("--disable-libiscsi")
                .arg("--disable-libnfs")
                .arg("--disable-libpmem")
                .arg("--disable-libssh")
                .arg("--disable-libudev")
                .arg("--disable-libusb")
                .arg("--disable-linux-aio")
                .arg("--disable-linux-io-uring")
                .arg("--disable-linux-user")
                .arg("--disable-live-block-migration")
                .arg("--disable-lzfse")
                .arg("--disable-lzo")
                .arg("--disable-l2tpv3")
                .arg("--disable-malloc-trim")
                .arg("--disable-mpath")
                .arg("--disable-multiprocess")
                .arg("--disable-netmap")
                .arg("--disable-nettle")
                .arg("--disable-numa")
                .arg("--disable-nvmm")
                .arg("--disable-opengl")
                .arg("--disable-oss")
                .arg("--disable-pa")
                .arg("--disable-parallels")
                .arg("--disable-plugins")
                .arg("--disable-png")
                .arg("--disable-pvrdma")
                .arg("--disable-qcow1")
                .arg("--disable-qed")
                .arg("--disable-qga-vss")
                .arg("--disable-rbd")
                .arg("--disable-rdma")
                .arg("--disable-replication")
                .arg("--disable-sdl")
                .arg("--disable-sdl-image")
                .arg("--disable-seccomp")
                .arg("--disable-selinux")
                .arg("--disable-slirp-smbd")
                .arg("--disable-smartcard")
                .arg("--disable-snappy")
                .arg("--disable-sparse")
                .arg("--disable-spice")
                .arg("--disable-spice-protocol")
                .arg("--disable-tools")
                .arg("--disable-tpm")
                .arg("--disable-usb-redir")
                .arg("--disable-user")
                .arg("--disable-u2f")
                .arg("--disable-vde")
                .arg("--disable-vdi")
                .arg("--disable-vduse-blk-export")
                .arg("--disable-vhost-crypto")
                .arg("--disable-vhost-kernel")
                .arg("--disable-vhost-net")
                .arg("--disable-vhost-user-blk-server")
                .arg("--disable-vhost-vdpa")
                .arg("--disable-virglrenderer")
                .arg("--disable-virtfs")
                .arg("--disable-virtiofsd")
                .arg("--disable-vmnet")
                .arg("--disable-vnc")
                .arg("--disable-vnc-jpeg")
                .arg("--disable-vnc-sasl")
                .arg("--disable-vte")
                .arg("--disable-vvfat")
                .arg("--disable-whpx")
                .arg("--disable-xen")
                .arg("--disable-xen-pci-passthrough")
                .arg("--disable-xkbcommon")
                .arg("--disable-zstd")
                .status()
                .expect("Configure failed");
        }
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
        build_dir.join(format!("libqemu-{cpu_target}-{target_suffix}.fa.p")),
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

    if emulation_mode == "usermode" {
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
            .arg("--end-group")
            .status()
            .expect("Partial linked failure");
    } else {
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
            .arg("--end-group")
            .status()
            .expect("Partial linked failure");
    }

    Command::new("ar")
        .current_dir(out_dir_path)
        .arg("crs")
        .arg("libqemu-partially-linked.a")
        .arg("libqemu-partially-linked.o")
        .status()
        .expect("Ar creation");

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static=qemu-partially-linked");
    println!("cargo:rustc-link-lib=rt");
    println!("cargo:rustc-link-lib=gmodule-2.0");
    println!("cargo:rustc-link-lib=glib-2.0");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=z");
    #[cfg(all(feature = "slirp", feature = "systemmode"))]
    println!("cargo:rustc-link-lib=slirp");

    if emulation_mode == "systemmode" {
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

    if emulation_mode == "usermode" {
        let qasan_dir = Path::new("libqasan");
        let qasan_dir = fs::canonicalize(qasan_dir).unwrap();

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
