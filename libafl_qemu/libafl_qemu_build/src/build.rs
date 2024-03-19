use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use which::which;

const QEMU_URL: &str = "https://github.com/AFLplusplus/qemu-libafl-bridge";
const QEMU_DIRNAME: &str = "qemu-libafl-bridge";
const QEMU_REVISION: &str = "f282d6aef5e28421255293ebbb52d835281f2730";

pub struct BuildResult {
    pub qemu_path: PathBuf,
    pub build_dir: PathBuf,
}

fn build_dep_check(tools: &[&str]) {
    for tool in tools {
        which(tool).unwrap_or_else(|_| panic!("Build tool {tool} not found"));
    }
}

#[allow(clippy::too_many_lines, clippy::missing_panics_doc)]
#[must_use]
pub fn build(
    cpu_target: &str,
    is_big_endian: bool,
    is_usermode: bool,
    jobs: Option<u32>,
) -> BuildResult {
    let mut cpu_target = cpu_target.to_string();
    // qemu-system-arm supports both big and little endian configurations and so
    // therefore the "be" feature should ignored in this configuration. Also
    // ignore the feature if we are running in clippy which enables all the
    // features at once (disabling the check for mutually exclusive options)
    // resulting in cpu_target being set to 'x86_64' above which obviously
    // doesn't support BE.
    if is_big_endian && cpu_target == "arm" && is_usermode && !cfg!(feature = "clippy") {
        // We have told rustc which CPU target to use above (it doesn't need
        // to make any changes for endianness), however, we need QEMU to be
        // built for the right endian-ness, so we update the cpu_target for
        // here on down
        cpu_target += "eb";
    }

    if !is_big_endian && cpu_target == "mips" && !cfg!(feature = "clippy") {
        cpu_target += "el";
    }

    let custom_qemu_dir = env::var_os("CUSTOM_QEMU_DIR").map(|x| x.to_string_lossy().to_string());
    let custom_qemu_no_build = env::var("CUSTOM_QEMU_NO_BUILD").is_ok();
    let custom_qemu_no_configure = env::var("CUSTOM_QEMU_NO_CONFIGURE").is_ok();
    println!("cargo:rerun-if-env-changed=CUSTOM_QEMU_DIR");
    println!("cargo:rerun-if-env-changed=CUSTOM_QEMU_NO_BUILD");
    println!("cargo:rerun-if-env-changed=CUSTOM_QEMU_NO_CONFIGURE");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    let out_dir_path = Path::new(&out_dir);
    let mut target_dir = out_dir_path.to_path_buf();
    target_dir.pop();
    target_dir.pop();
    target_dir.pop();

    build_dep_check(&["git", "make"]);

    let cc_compiler = cc::Build::new().cpp(false).get_compiler();
    let cpp_compiler = cc::Build::new().cpp(true).get_compiler();

    let qemu_path = if let Some(qemu_dir) = custom_qemu_dir.as_ref() {
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
            println!("cargo:warning=Qemu not found, cloning with git ({QEMU_REVISION})...");
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

    let target_suffix = if is_usermode {
        "linux-user".to_string()
    } else {
        "softmmu".to_string()
    };

    let (output_lib, output_lib_link) = if is_usermode {
        (
            build_dir.join(format!("libqemu-{cpu_target}.so")),
            format!("qemu-{cpu_target}"),
        )
    } else {
        (
            build_dir.join(format!("libqemu-system-{cpu_target}.so")),
            format!("qemu-system-{cpu_target}"),
        )
    };

    // println!("cargo:rerun-if-changed={}", output_lib.to_string_lossy());

    if !output_lib.is_file() || (custom_qemu_dir.is_some() && !custom_qemu_no_build) {
        /*drop(
            Command::new("make")
                .current_dir(&qemu_path)
                .arg("distclean")
                .status(),
        );*/
        let mut cmd = Command::new("./configure");
        cmd.current_dir(&qemu_path)
            //.arg("--as-static-lib")
            .env("__LIBAFL_QEMU_BUILD_OUT", build_dir.join("linkinfo.json"))
            .env("__LIBAFL_QEMU_BUILD_CC", cc_compiler.path())
            .env("__LIBAFL_QEMU_BUILD_CXX", cpp_compiler.path())
            .arg(&format!(
                "--cc={}",
                qemu_path.join("linker_interceptor.py").display()
            ))
            .arg(&format!(
                "--cxx={}",
                qemu_path.join("linker_interceptor++.py").display()
            ))
            .arg("--as-shared-lib")
            .arg(&format!("--target-list={cpu_target}-{target_suffix}"));
        if cfg!(feature = "debug_assertions") {
            cmd.arg("--enable-debug");
        }
        if is_usermode && !custom_qemu_no_configure {
            cmd.args([
                "--disable-bsd-user",
                "--disable-fdt",
                "--disable-system",
                "--disable-capstone",
            ]);
        } else if !custom_qemu_no_configure {
            cmd.arg(if cfg!(feature = "slirp") {
                "--enable-slirp"
            } else {
                "--disable-slirp"
            })
            .arg("--enable-fdt=internal")
            .arg("--audio-drv-list=")
            .arg("--disable-af-xdp")
            .arg("--disable-alsa")
            .arg("--disable-attr")
            .arg("--disable-auth-pam")
            .arg("--disable-dbus-display")
            .arg("--disable-bochs")
            .arg("--disable-bpf")
            .arg("--disable-brlapi")
            .arg("--disable-bsd-user")
            .arg("--disable-bzip2")
            .arg("--disable-capstone")
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
            .arg("--disable-sndio")
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
            .arg("--disable-tests");
        }

        cmd.status().expect("Configure failed");
        if let Some(j) = jobs {
            Command::new("make")
                .current_dir(&build_dir)
                .arg("-j")
                .arg(&format!("{j}"))
                .env("V", "1")
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

    /*
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
    */

    if cfg!(feature = "shared") {
        println!(
            "cargo:rustc-link-search=native={}",
            build_dir.to_string_lossy()
        );
        println!("cargo:rustc-link-lib=dylib={output_lib_link}");
    } else {
        let compile_commands_string = &fs::read_to_string(build_dir.join("linkinfo.json"))
            .expect("Failed to read linkinfo.json");

        let linkinfo = json::parse(compile_commands_string).expect("Failed to parse linkinfo.json");

        let mut cmd = vec![];
        for arg in linkinfo["cmd"].members() {
            cmd.push(
                arg.as_str()
                    .expect("linkinfo.json `cmd` values must be strings"),
            );
        }

        assert!(cpp_compiler
            .to_command()
            .current_dir(&build_dir)
            .arg("-o")
            .arg("libqemu-partially-linked.o")
            .arg("-r")
            .args(cmd)
            .status()
            .expect("Partial linked failure")
            .success());

        /* // Old manual linking, kept here for reference and debugging
        if is_usermode {
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
                .arg(format!("{}/gdbstub/libgdb_user.fa", build_dir.display()))
                .arg("--no-whole-archive")
                .arg(format!("{}/libqemuutil.a", build_dir.display()))
                .arg(format!("{}/libhwcore.fa", build_dir.display()))
                .arg(format!("{}/libqom.fa", build_dir.display()))
                .arg(format!("{}/gdbstub/libgdb_user.fa", build_dir.display()))
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
                .arg(format!("{}/gdbstub/libgdb_softmmu.fa", build_dir.display()))
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
                    "{}/subprojects/dtc/libfdt/libfdt.a",
                    build_dir.display()
                ))
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
                .arg(format!("{}/libmigration.fa", build_dir.display()))
                .arg(format!("{}/libhwcore.fa", build_dir.display()))
                .arg(format!("{}/libqom.fa", build_dir.display()))
                .arg(format!("{}/gdbstub/libgdb_softmmu.fa", build_dir.display()))
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
        }*/

        Command::new("ar")
            .current_dir(out_dir_path)
            .arg("crs")
            .arg("libqemu-partially-linked.a")
            .arg(build_dir.join("libqemu-partially-linked.o"))
            .status()
            .expect("Ar creation");

        println!("cargo:rustc-link-search=native={out_dir}");
        println!("cargo:rustc-link-lib=static=qemu-partially-linked");

        for arg in linkinfo["search"].members() {
            let val = arg
                .as_str()
                .expect("linkinfo.json `search` values must be strings");
            println!("cargo:rustc-link-search={val}");
        }

        for arg in linkinfo["libs"].members() {
            let val = arg
                .as_str()
                .expect("linkinfo.json `libs` values must be strings");
            println!("cargo:rustc-link-lib={val}");
        }
    }

    /*
    println!("cargo:rustc-link-lib=rt");
    println!("cargo:rustc-link-lib=gmodule-2.0");
    println!("cargo:rustc-link-lib=glib-2.0");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=z");
    // if keyutils is available, qemu meson script will compile code with keyutils.
    // therefore, we need to link with keyutils if our system have libkeyutils.
    let _: Result<pkg_config::Library, pkg_config::Error> =
        pkg_config::Config::new().probe("libkeyutils");
    */

    if !is_usermode {
        //println!("cargo:rustc-link-lib=pixman-1");
        //if env::var("LINK_SLIRP").is_ok() || cfg!(feature = "slirp") {
        //    println!("cargo:rustc-link-lib=slirp");
        //}

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

    BuildResult {
        qemu_path,
        build_dir,
    }
}
