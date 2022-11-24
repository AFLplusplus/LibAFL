use std::{fs, path::Path};

mod build;
mod bindings;

pub use build::build;

const COMPILE_COMMANDS: &str = "compile_commands.json";
const QEMU_MAIN_FILE: &str = "/softmmu/main.c";
const QEMU_MAIN_OBJECT: &str = "qemu-system-$ARCH.p/softmmu_main.c.o";


pub fn build_with_bindings(cpu_target: &str, is_big_endian: bool, is_usermode: bool, jobs: Option<u32>, cross_cc: &str, bindings_file: &Path) {
    println!("cargo:rerun-if-changed={}", bindings_file.display());
    
    let build_dir = build::build(cpu_target, is_big_endian, is_usermode, jobs, cross_cc);

    let bind = bindings::generate(&build_dir, cpu_target).expect("Failed to generate the bindings");
    bind.write_to_file(bindings_file).expect("Faield to write to the bindings file");
}

pub(crate) fn qemu_bindgen_clang_args(build_dir: &Path, cpu_target: &str) -> Vec<String> {
    // load compile commands
    let compile_commands_string = &fs::read_to_string(build_dir.join(COMPILE_COMMANDS))
        .expect("failed to read compile commands");

    let compile_commands =
        json::parse(compile_commands_string).expect("failed to parse compile commands");

    // find main object
    let entry = compile_commands
        .members()
        .find(|entry| {
            entry["output"] == QEMU_MAIN_OBJECT.replace(ARCH_PLACEHOLDER, arch.as_str())
                || entry["file"]
                    .as_str()
                    .map(|file| file.ends_with(QEMU_MAIN_FILE))
                    .unwrap_or(false)
        })
        .expect("didn't find compile command for qemu-system-arm");

    // get main object build command
    let command = entry["command"].as_str().expect("command is a string");

    // filter define and include args
    let mut clang_args = vec![];
    let mut include_arg = false;
    for arg in shell_words::split(command)
        .expect("failed to parse command")
        .into_iter()
        .skip(1)
    {
        if arg.starts_with("-D") {
            clang_args.push(arg)
        } else if let Some(incpath) = arg.strip_prefix("-I") {
            clang_args.push(format!("-I{}", include_path(build_dir, incpath)));
        } else if arg == "-iquote" || arg == "-isystem" {
            include_arg = true;
            clang_args.push(arg)
        } else if include_arg {
            include_arg = false;
            clang_args.push(include_path(build_dir, &arg))
        }
    }

    // add include dirs
    clang_args.push("-Iqemu/include".to_owned());
    clang_args.push("-iquote".to_owned());
    clang_args.push(format!("qemu/target/{}", arch.target()));

    clang_args
}

