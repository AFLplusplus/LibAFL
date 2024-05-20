#![forbid(unexpected_cfgs)]
#![allow(clippy::missing_panics_doc)]

use std::{
    collections::hash_map,
    env, fs,
    fs::File,
    hash::Hasher,
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    ptr::addr_of_mut,
};

use regex::Regex;
use rustc_version::Version;
use which::which;

mod bindings;
mod build;

pub use build::build;

const LLVM_VERSION_MAX: i32 = 33;

static mut CARGO_RPATH: Option<Vec<String>> = None;
static CARGO_RPATH_SEPARATOR: &str = "|";

pub fn cargo_add_rpath(rpath: &str) {
    unsafe {
        if let Some(rpaths) = &mut *addr_of_mut!(CARGO_RPATH) {
            rpaths.push(rpath.to_string());
        } else {
            CARGO_RPATH = Some(vec![rpath.to_string()]);
        }
    }
}

pub fn cargo_propagate_rpath() {
    unsafe {
        if let Some(cargo_cmds) = &mut *addr_of_mut!(CARGO_RPATH) {
            let rpath = cargo_cmds.join(CARGO_RPATH_SEPARATOR);
            println!("cargo:rpath={rpath}");
        }
    }
}

/// Must be called from final binary crates
pub fn build_libafl_qemu() {
    // Add rpath if there are some
    if let Some(rpaths) = env::var_os("DEP_QEMU_RPATH") {
        let rpaths: Vec<&str> = rpaths
            .to_str()
            .expect("Cannot convert OsString to str")
            .split(CARGO_RPATH_SEPARATOR)
            .collect();
        for rpath in rpaths {
            println!("cargo:rustc-link-arg-bins=-Wl,-rpath,{rpath}");
        }
    }
}

pub fn build_with_bindings(
    cpu_target: &str,
    is_big_endian: bool,
    is_usermode: bool,
    jobs: Option<u32>,
    bindings_file: &Path,
) {
    let build_result = build::build(cpu_target, is_big_endian, is_usermode, jobs);

    let clang_args = qemu_bindgen_clang_args(
        &build_result.qemu_path,
        &build_result.build_dir,
        cpu_target,
        is_usermode,
    );

    let bind = bindings::generate(&build_result.build_dir, cpu_target, clang_args)
        .expect("Failed to generate the bindings");

    // Write the final bindings
    fs::write(bindings_file, bind.to_string()).expect("Unable to write file");

    cargo_propagate_rpath();
}

// For bindgen, the llvm version must be >= of the rust llvm version
fn find_llvm_config() -> Result<String, String> {
    if let Ok(var) = env::var("LLVM_CONFIG") {
        return Ok(var);
    }

    let rustc_llvm_ver = find_rustc_llvm_version().unwrap();
    for version in (rustc_llvm_ver..=LLVM_VERSION_MAX).rev() {
        let llvm_config_name: String = format!("llvm-config-{version}");
        if which(&llvm_config_name).is_ok() {
            return Ok(llvm_config_name);
        }
    }

    if which("llvm-config").is_ok() {
        if let Some(ver) = find_llvm_version("llvm-config".to_owned()) {
            if ver >= rustc_llvm_ver {
                return Ok("llvm-config".to_owned());
            }
        }
    }

    Err("could not find llvm-config".to_owned())
}

fn exec_llvm_config(llvm_config: String, args: &[&str]) -> String {
    match Command::new(llvm_config).args(args).output() {
        Ok(output) => String::from_utf8(output.stdout)
            .expect("Unexpected llvm-config output")
            .trim()
            .to_string(),
        Err(e) => panic!("Could not execute llvm-config: {e}"),
    }
}

fn find_llvm_version(llvm_config: String) -> Option<i32> {
    let output = exec_llvm_config(llvm_config, &["--version"]);
    if let Some(major) = output.split('.').collect::<Vec<&str>>().first() {
        if let Ok(res) = major.parse::<i32>() {
            return Some(res);
        }
    }
    None
}

fn exec_rustc(args: &[&str]) -> String {
    let rustc = env::var("RUSTC").unwrap();
    match Command::new(rustc).args(args).output() {
        Ok(output) => String::from_utf8(output.stdout)
            .expect("Unexpected rustc output")
            .trim()
            .to_string(),
        Err(e) => panic!("Could not execute rustc: {e}"),
    }
}

fn find_rustc_llvm_version() -> Option<i32> {
    let output = exec_rustc(&["--verbose", "--version"]);
    let ver = output.split(':').last().unwrap().trim();
    if let Some(major) = ver.split('.').collect::<Vec<&str>>().first() {
        if let Ok(res) = major.parse::<i32>() {
            return Some(res);
        }
    }
    None
}

//linux-user_main.c.o libqemu-x86_64-linux-user.fa.p

fn qemu_bindgen_clang_args(
    qemu_dir: &Path,
    build_dir: &Path,
    cpu_target: &str,
    is_usermode: bool,
) -> Vec<String> {
    if env::var("LLVM_CONFIG_PATH").is_err() {
        let found = find_llvm_config().expect("Cannot find a suitable llvm-config, it must be a version equal or greater than the rustc LLVM version");
        env::set_var("LLVM_CONFIG_PATH", found);
    }

    // load compile commands
    let compile_commands_string = &fs::read_to_string(build_dir.join("compile_commands.json"))
        .expect("failed to read compile commands");

    let compile_commands =
        json::parse(compile_commands_string).expect("Failed to parse compile commands");

    let (main_file, main_obj) = if is_usermode {
        (
            "/linux-user/main.c",
            format!("libqemu-{cpu_target}-linux-user.fa.p/linux-user_main.c.o"),
        )
    } else {
        (
            "/system/main.c",
            format!("libqemu-system-{cpu_target}.so.p/system_main.c.o"),
        )
    };

    // find main object
    let entry = compile_commands
        .members()
        .find(|entry| {
            entry["output"] == main_obj
                || entry["file"]
                    .as_str()
                    .map_or(false, |file| file.ends_with(main_file))
        })
        .expect("Didn't find compile command for qemu-system-arm");

    // get main object build command
    let command = entry["command"].as_str().expect("Command is a string");

    // filter define and include args
    let mut clang_args = vec![];
    let mut include_arg = false;
    for arg in shell_words::split(command)
        .expect("failed to parse command")
        .into_iter()
        .skip(1)
    {
        if arg.starts_with("-D") {
            clang_args.push(arg);
        } else if let Some(incpath) = arg.strip_prefix("-I") {
            clang_args.push(format!("-I{}", include_path(build_dir, incpath)));
        } else if arg == "-iquote" || arg == "-isystem" {
            include_arg = true;
            clang_args.push(arg);
        } else if include_arg {
            include_arg = false;
            clang_args.push(include_path(build_dir, &arg));
        }
    }

    let target_arch_dir = match cpu_target {
        "x86_64" => format!("-I{}/target/i386", qemu_dir.display()),
        "aarch64" => format!("-I{}/target/arm", qemu_dir.display()),
        _ => format!("-I{}/target/{cpu_target}", qemu_dir.display()),
    };

    // add include dirs
    clang_args.push(format!("-I{}", qemu_dir.display()));
    clang_args.push(format!("-I{}/include", qemu_dir.display()));
    clang_args.push(format!("-I{}/quote", qemu_dir.display()));
    clang_args.push(target_arch_dir);

    clang_args
}

fn include_path(build_dir: &Path, path: &str) -> String {
    let include_path = PathBuf::from(path);

    if include_path.is_absolute() {
        path.to_string()
    } else {
        // make include path absolute
        build_dir.join(include_path).display().to_string()
    }
}

/// If `fresh_content` != `content_file_to_update` (the file is read directly if `content_file_to_update` is None), update the file. prefix is not considered for comparison.
/// If a prefix is given, it will be added as the first line of the file.
pub fn store_generated_content_if_different(
    file_to_update: &PathBuf,
    fresh_content: &[u8],
    content_file_to_update: Option<Vec<u8>>,
    first_line_prefix: Option<&str>,
    force_regeneration: bool,
) {
    let mut must_rewrite_file = true;

    // Check if equivalent file already exists without relying on filesystem timestamp.
    let mut file_to_check =
        if let Ok(mut wrapper_file) = File::options().read(true).write(true).open(file_to_update) {
            let existing_file_content = content_file_to_update.unwrap_or_else(|| {
                let mut content = Vec::with_capacity(fresh_content.len());
                wrapper_file.read_to_end(content.as_mut()).unwrap();
                content
            });

            if !force_regeneration {
                let mut existing_wrapper_hasher = hash_map::DefaultHasher::new();
                existing_wrapper_hasher.write(existing_file_content.as_ref());

                let mut wrapper_h_hasher = hash_map::DefaultHasher::new();
                wrapper_h_hasher.write(fresh_content);

                // Check if wrappers are the same
                if existing_wrapper_hasher.finish() == wrapper_h_hasher.finish() {
                    must_rewrite_file = false;
                }
            }

            // Reset file cursor if it's going to be rewritten
            if must_rewrite_file {
                wrapper_file.set_len(0).expect("Could not set file len");
                wrapper_file
                    .seek(SeekFrom::Start(0))
                    .expect("Could not seek file to beginning");
            }

            wrapper_file
        } else {
            File::create(file_to_update)
                .unwrap_or_else(|_| panic!("Could not create {}", file_to_update.display()))
        };

    if must_rewrite_file {
        if let Some(prefix) = first_line_prefix {
            writeln!(&file_to_check, "{prefix}").expect("Could not write prefix");
        }

        file_to_check
            .write_all(fresh_content)
            .unwrap_or_else(|_| panic!("Unable to write in {}", file_to_update.display()));
    }
}
#[rustversion::nightly]
pub fn maybe_generate_stub_bindings(
    cpu_target: &str,
    emulation_mode: &str,
    stub_bindings_file: &PathBuf,
    bindings_file: &PathBuf,
) {
    if cpu_target == "x86_64" && emulation_mode == "usermode" {
        let current_rustc_version =
            rustc_version::version().expect("Could not get current rustc version");
        let semver_re = Regex::new(r"/\* (.*) \*/").unwrap();

        // We only try to store the stub if the current rustc version is strictly bigger than the one used to generate
        // the versioned stub.
        let (try_generate, force_regeneration, stub_content): (bool, bool, Option<Vec<u8>>) =
            if let Ok(stub_file) = File::open(stub_bindings_file) {
                let mut stub_rdr = BufReader::new(stub_file);

                let mut first_line = String::new();
                let mut stub_content = Vec::<u8>::new();
                assert!(
                    stub_rdr
                        .read_line(&mut first_line)
                        .expect("Could not read first line")
                        > 0,
                    "Error while reading first line."
                );

                if let Some((_, [version_str])) = semver_re
                    .captures_iter(&first_line)
                    .next()
                    .map(|caps| caps.extract())
                {
                    // The first line matches the regex

                    if let Ok(version) = Version::parse(version_str) {
                        // The first line contains a version

                        stub_rdr
                            .read_to_end(&mut stub_content)
                            .expect("could not read stub content");
                        (current_rustc_version > version, false, Some(stub_content))
                    } else {
                        stub_rdr.seek(SeekFrom::Start(0)).unwrap();
                        stub_rdr
                            .read_to_end(&mut stub_content)
                            .expect("could not read stub content");

                        (true, true, Some(stub_content))
                    }
                } else {
                    stub_rdr.seek(SeekFrom::Start(0)).unwrap();
                    stub_rdr
                        .read_to_end(&mut stub_content)
                        .expect("could not read stub content");

                    (true, true, Some(stub_content))
                }
            } else {
                // No stub file stored
                (true, true, None)
            };

        let header = format!("/* {current_rustc_version} */");

        if try_generate {
            store_generated_content_if_different(
                stub_bindings_file,
                fs::read(bindings_file)
                    .expect("Could not read generated bindings file")
                    .as_slice(),
                stub_content,
                Some(header.as_str()),
                force_regeneration,
            );
        }
    }
}

#[rustversion::not(nightly)]
pub fn maybe_generate_stub_bindings(
    _cpu_target: &str,
    _emulation_mode: &str,
    _stub_bindings_file: &PathBuf,
    _bindings_file: &PathBuf,
) {
    // Do nothing
}
