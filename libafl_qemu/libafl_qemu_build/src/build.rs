use core::str::FromStr;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use which::which;

use crate::cargo_add_rpath;

pub const QEMU_URL: &str = "https://github.com/AFLplusplus/qemu-libafl-bridge";
pub const QEMU_DIRNAME: &str = "qemu-libafl-bridge";
pub const QEMU_REVISION: &str = "2a676d9cd8c474b5c0db1d77d2769e56e2ed8524";

pub struct BuildResult {
    pub qemu_path: PathBuf,
    pub build_dir: PathBuf,
}

fn build_dep_check(tools: &[&str]) {
    for tool in tools {
        which(tool).unwrap_or_else(|_| panic!("Build tool {tool} not found"));
    }
}

fn get_config_signature(config_cmd: &Command) -> String {
    let mut signature_string = String::new();

    // Command env
    let config_env: String = config_cmd
        .get_envs()
        .map(|(key, value)| {
            format!(
                "\t{}={}",
                key.to_str().expect("Couldn't convert OsStr to str"),
                if let Some(v) = value {
                    v.to_str().expect("Could't convert OsStr to str")
                } else {
                    ""
                }
            )
        })
        .reduce(|acc, elt| format!("{acc}\n{elt}"))
        .into_iter()
        .collect();
    signature_string += format!("Environment:\n{config_env}").as_str();

    // Command args
    let config_args: String = config_cmd
        .get_args()
        .map(|arg| format!("\t{}", arg.to_str().expect("Couldn't convert OsStr to str")))
        .reduce(|acc, arg| format!("{acc}\n{arg}"))
        .into_iter()
        .collect();
    signature_string += format!("\n\nArguments:\n{config_args}").as_str();

    signature_string
}

#[expect(clippy::too_many_lines)]
fn configure_qemu(
    cc_compiler: &cc::Tool,
    cpp_compiler: &cc::Tool,
    qemu_path: &PathBuf,
    build_dir: &Path,
    is_usermode: bool,
    cpu_target: &String,
    target_suffix: &String,
) -> Command {
    let mut cmd = Command::new("./configure");

    let linker_interceptor = qemu_path.join("linker_interceptor.py");
    let linker_interceptor_plus_plus = qemu_path.join("linker_interceptor++.py");

    println!("cargo:rerun-if-changed={}", linker_interceptor.display());
    println!(
        "cargo:rerun-if-changed={}",
        linker_interceptor_plus_plus.display()
    );

    // Set common options for usermode and systemmode
    cmd.current_dir(qemu_path)
        .env("__LIBAFL_QEMU_CONFIGURE", "")
        .env("__LIBAFL_QEMU_BUILD_OUT", build_dir.join("linkinfo.json"))
        .env("__LIBAFL_QEMU_BUILD_CC", cc_compiler.path())
        .env("__LIBAFL_QEMU_BUILD_CXX", cpp_compiler.path())
        .arg(format!("--cc={}", linker_interceptor.display()))
        .arg(format!("--cxx={}", linker_interceptor_plus_plus.display()))
        .arg("--as-shared-lib")
        .arg(format!("--target-list={cpu_target}-{target_suffix}"))
        .arg("--disable-bsd-user")
        // .arg("--disable-capstone")
        .arg("--disable-docs")
        .arg("--disable-tests")
        .arg("--disable-tools");

    if cfg!(feature = "paranoid_debug") {
        cmd.arg("--enable-debug").arg("--enable-debug-tcg");
    }

    if cfg!(feature = "qemu_sanitizers") {
        cmd.arg("--enable-asan");
    }

    if is_usermode {
        // Usermode options
        cmd.args(["--disable-fdt", "--disable-system", "--disable-docs"]);
    } else {
        // Systemmode options
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
        // .arg("--disable-gtk")
        // .arg("--disable-guest-agent")
        // .arg("--disable-guest-agent-msi")
        .arg("--disable-hvf")
        .arg("--disable-iconv")
        .arg("--disable-jack")
        .arg("--disable-keyring")
        // .arg("--disable-kvm")
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
        // .arg("--disable-live-block-migration")
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
        // .arg("--disable-pvrdma")
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
        .arg("--disable-zstd");
    }

    cmd
}

fn build_qemu(
    cc_compiler: &cc::Tool,
    cpp_compiler: &cc::Tool,
    build_dir: &PathBuf,
    jobs: Option<u32>,
) -> Command {
    let mut cmd = Command::new("make");

    cmd.current_dir(build_dir)
        .env("__LIBAFL_QEMU_CONFIGURE", "")
        .env("__LIBAFL_QEMU_BUILD_OUT", build_dir.join("linkinfo.json"))
        .env("__LIBAFL_QEMU_BUILD_CC", cc_compiler.path())
        .env("__LIBAFL_QEMU_BUILD_CXX", cpp_compiler.path())
        .arg("-j");

    if let Some(j) = jobs {
        cmd.arg(format!("{j}")).env("V", "1");
    }

    cmd
}

#[expect(clippy::too_many_lines, clippy::missing_panics_doc)]
#[must_use]
pub fn build(
    cpu_target: &str,
    is_big_endian: bool,
    is_usermode: bool,
    jobs: Option<u32>,
) -> BuildResult {
    let mut cpu_target = cpu_target.to_string();
    // qemu-system-arm supports both big and little endian configurations and so
    // the "be" feature should be ignored in this configuration. Also
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

    let libafl_qemu_dir = env::var_os("LIBAFL_QEMU_DIR").map(|x| x.to_string_lossy().to_string());
    let libafl_qemu_clone_dir =
        env::var_os("LIBAFL_QEMU_CLONE_DIR").map(|x| x.to_string_lossy().to_string());
    let libafl_qemu_force_configure = env::var("LIBAFL_QEMU_FORCE_CONFIGURE").is_ok();
    let libafl_qemu_no_build = env::var("LIBAFL_QEMU_NO_BUILD").is_ok();

    println!("cargo:rerun-if-env-changed=LIBAFL_QEMU_DIR");
    println!("cargo:rerun-if-env-changed=LIBAFL_QEMU_CLONE_DIR");
    println!("cargo:rerun-if-env-changed=LIBAFL_QEMU_FORCE_BUILD");
    println!("cargo:rerun-if-env-changed=LIBAFL_QEMU_FORCE_CONFIGURE");
    println!("cargo:rerun-if-env-changed=LIBAFL_QEMU_NO_BUILD");

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

    let libafl_qemu_dir = if let Some(qemu_dir) = libafl_qemu_dir.as_ref() {
        if libafl_qemu_clone_dir.is_some() {
            println!(
                "cargo:warning=LIBAFL_QEMU_DIR and LIBAFL_QEMU_CLONE_DIR are both set. LIBAFL_QEMU_DIR will be considered in priority"
            );
        }

        Path::new(&qemu_dir).to_path_buf()
    } else {
        let qemu_path = if let Some(clone_dir) = &libafl_qemu_clone_dir {
            PathBuf::from(clone_dir)
        } else {
            target_dir.join(QEMU_DIRNAME)
        };

        let qemu_rev = target_dir.join("QEMU_REVISION");
        if qemu_rev.exists()
            && fs::read_to_string(&qemu_rev).expect("Failed to read QEMU_REVISION") != QEMU_REVISION
        {
            drop(fs::remove_dir_all(&qemu_path));
        }

        if !qemu_path.is_dir() {
            println!("cargo:warning=Qemu not found, cloning with git ({QEMU_REVISION})...");
            fs::create_dir_all(&qemu_path).unwrap();
            assert!(
                Command::new("git")
                    .current_dir(&qemu_path)
                    .arg("init")
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                Command::new("git")
                    .current_dir(&qemu_path)
                    .arg("remote")
                    .arg("add")
                    .arg("origin")
                    .arg(QEMU_URL)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                Command::new("git")
                    .current_dir(&qemu_path)
                    .arg("fetch")
                    .arg("--depth")
                    .arg("1")
                    .arg("origin")
                    .arg(QEMU_REVISION)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(
                Command::new("git")
                    .current_dir(&qemu_path)
                    .arg("checkout")
                    .arg("FETCH_HEAD")
                    .status()
                    .unwrap()
                    .success()
            );
            fs::write(&qemu_rev, QEMU_REVISION).unwrap();
        }

        qemu_path
    };

    let libafl_qemu_build_dir = libafl_qemu_dir.join("build");
    let config_signature_path = libafl_qemu_build_dir.join("libafl_config");

    let target_suffix = if is_usermode {
        "linux-user".to_string()
    } else {
        "softmmu".to_string()
    };

    let (output_lib, output_lib_link) = if is_usermode {
        (
            libafl_qemu_build_dir.join(format!("libqemu-{cpu_target}.so")),
            format!("qemu-{cpu_target}"),
        )
    } else {
        (
            libafl_qemu_build_dir.join(format!("libqemu-system-{cpu_target}.so")),
            format!("qemu-system-{cpu_target}"),
        )
    };

    let libafl_config_old_signature = fs::read_to_string(&config_signature_path);

    let mut config_cmd = configure_qemu(
        &cc_compiler,
        &cpp_compiler,
        &libafl_qemu_dir,
        &libafl_qemu_build_dir,
        is_usermode,
        &cpu_target,
        &target_suffix,
    );

    let current_config_signature = get_config_signature(&config_cmd);
    let must_reconfigure = if libafl_qemu_force_configure {
        // If the user asked to reconfigure, do so
        true
    } else if let Ok(libafl_config_old_signature) = libafl_config_old_signature {
        if libafl_config_old_signature == current_config_signature {
            // Signature match, do not reconfigure
            false
        } else {
            println!("cargo:warning=QEMU configuration is outdated. Reconfiguring...");
            true
        }
    } else {
        // In worst scenario, reconfigure
        true
    };

    if must_reconfigure {
        assert!(
            config_cmd
                .status()
                .expect("Invoking Configure failed")
                .success(),
            "Configure didn't finish successfully"
        );

        // Config succeeded at this point, (over)write the signature file
        fs::write(config_signature_path, current_config_signature)
            .expect("Couldn't write config signature file.");
    }

    // Always build by default, make will detect if it is necessary to rebuild qemu
    if !libafl_qemu_no_build {
        let mut build_cmd = build_qemu(&cc_compiler, &cpp_compiler, &libafl_qemu_build_dir, jobs);

        assert!(
            build_cmd.status().expect("Invoking Make Failed").success(),
            "Make didn't finish successfully"
        );
    }

    assert!(output_lib.is_file()); // Make sure this isn't very very wrong

    let compile_commands_string = &fs::read_to_string(libafl_qemu_build_dir.join("linkinfo.json"))
        .expect("Failed to read linkinfo.json");

    let linkinfo = json::parse(compile_commands_string).expect("Failed to parse linkinfo.json");

    for source in linkinfo["sources"].members() {
        let source_path = PathBuf::from_str(source.as_str().unwrap()).unwrap();

        let source_path = if source_path.is_relative() {
            libafl_qemu_build_dir.join(source_path)
        } else {
            source_path
        };

        println!("cargo:rerun-if-changed={}", source_path.display());
    }

    if cfg!(feature = "shared") {
        let qemu_build_dir_str = libafl_qemu_build_dir
            .to_str()
            .expect("Could not convert to str");
        println!("cargo:rustc-link-search=native={qemu_build_dir_str}");
        println!("cargo:rustc-link-lib=dylib={output_lib_link}");
        cargo_add_rpath(qemu_build_dir_str);
    } else {
        let mut cmd = vec![];
        for arg in linkinfo["cmd"].members() {
            cmd.push(
                arg.as_str()
                    .expect("linkinfo.json `cmd` values must be strings"),
            );
        }

        let mut link_command = cpp_compiler.to_command();

        link_command
            .current_dir(&libafl_qemu_build_dir)
            .arg("-o")
            .arg("libqemu-partially-linked.o")
            .arg("-r")
            .args(cmd);

        let link_str = format!("{link_command:?}");

        let output = match link_command.output() {
            Ok(output) => output,
            Err(e) => panic!("Command {link_command:?} failed: {e:?}"),
        };

        if !output.status.success() {
            fs::write(libafl_qemu_build_dir.join("link.command"), link_str)
                .expect("Link command failed.");
            fs::write(libafl_qemu_build_dir.join("link.stdout"), &output.stdout)
                .expect("Link stdout failed.");
            fs::write(libafl_qemu_build_dir.join("link.stderr"), &output.stderr)
                .expect("Link stderr failed.");
            panic!("Linking failed.");
        }

        Command::new("ar")
            .current_dir(out_dir_path)
            .arg("crs")
            .arg("libqemu-partially-linked.a")
            .arg(libafl_qemu_build_dir.join("libqemu-partially-linked.o"))
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

        for arg in linkinfo["rpath"].members() {
            let val = arg
                .as_str()
                .expect("linkinfo.json `libs` values must be strings")
                .to_string()
                .replace(
                    "$ORIGIN",
                    libafl_qemu_build_dir
                        .as_os_str()
                        .to_str()
                        .expect("Could not convert OsStr to str"),
                );
            cargo_add_rpath(&val);
        }
    }

    if cfg!(feature = "qemu_sanitizers") {
        println!("cargo:rustc-link-lib=ubsan");
        println!("cargo:rustc-link-lib=asan");
    }

    if !is_usermode {
        fs::create_dir_all(target_dir.join("pc-bios")).unwrap();
        for path in fs::read_dir(libafl_qemu_build_dir.join("pc-bios")).unwrap() {
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
        qemu_path: libafl_qemu_dir,
        build_dir: libafl_qemu_build_dir,
    }
}
