use std::{
    fs,
    path::{Path, PathBuf},
};

mod bindings;
mod build;

pub use build::build;

pub fn build_with_bindings(
    cpu_target: &str,
    is_big_endian: bool,
    is_usermode: bool,
    jobs: Option<u32>,
    bindings_file: &Path,
) {
    println!("cargo:rerun-if-changed={}", bindings_file.display());

    let (qemu_dir, build_dir) = build::build(cpu_target, is_big_endian, is_usermode, jobs);
    let clang_args = qemu_bindgen_clang_args(&qemu_dir, &build_dir, cpu_target, is_usermode);

    let bind = bindings::generate(&build_dir, cpu_target, clang_args)
        .expect("Failed to generate the bindings");
    bind.write_to_file(bindings_file)
        .expect("Faield to write to the bindings file");
}

//linux-user_main.c.o libqemu-x86_64-linux-user.fa.p

fn qemu_bindgen_clang_args(
    qemu_dir: &Path,
    build_dir: &Path,
    cpu_target: &str,
    is_usermode: bool,
) -> Vec<String> {
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
            "/softmmu/main.c",
            format!("qemu-system-{cpu_target}.p/softmmu_main.c.o"),
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
