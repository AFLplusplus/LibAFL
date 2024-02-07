#![allow(clippy::missing_panics_doc)]
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use regex::Regex;
use which::which;

mod bindings;
mod build;

pub use build::build;

const LLVM_VERSION_MAX: i32 = 33;

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
    bind.write_to_file(bindings_file)
        .expect("Faield to write to the bindings file");

    // """Fix""" the bindings here
    let contents =
        fs::read_to_string(bindings_file).expect("Should have been able to read the file");
    let re = Regex::new("(Option<\\s*)unsafe( extern \"C\" fn\\(data: u64)").unwrap();
    let replaced = re.replace_all(&contents, "$1$2");
    fs::write(bindings_file, replaced.as_bytes()).expect("Unable to write file");
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
