use core::error::Error;
use std::{
    env,
    process::{Command, exit},
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        exit(1);
    }
    let instance_idx: usize = args[1]
        .parse()
        .map_err(|e| format!("Failed to parse instance index '{}': {}", args[1], e))?;

    let ci_instances: usize = if let Ok(val) = env::var("CI_INSTANCES") {
        val.parse()
            .map_err(|e| format!("CI_INSTANCES must be a positive integer, got '{val}': {e}"))?
    } else {
        eprintln!("Error: CI_INSTANCES environment variable not set");
        exit(1);
    };

    let llvm_var: usize = if let Ok(val) = env::var("LLVM_VERSION") {
        val.parse()
            .map_err(|e| format!("LLVM_VERSION must be a positive integer, got '{val}': {e}"))?
    } else {
        eprintln!("Error: LLVM_VERSION environment variable not set");
        exit(1);
    };

    if env::var("LLVM_CONFIG").is_err() {
        unsafe {
            env::set_var("LLVM_CONFIG", format!("llvm-config-{llvm_var}"));
        }
    }

    // Exclude libafl_asan_libc since it is only a dummy library without any implementation anyway, but also because it needs to be built for `no_std`
    let the_command = concat!(
        "DOCS_RS=1 cargo hack check --workspace --each-feature --clean-per-run \
        --exclude-features=prelude,python,sancov_pcguard_edges,arm,aarch64,i386,be,systemmode,whole_archive \
        --no-dev-deps --exclude libafl_libfuzzer --exclude libafl_qemu --exclude libafl_qemu_sys --exclude libafl_asan_libc --print-command-list; ",
        "DOCS_RS=1 cargo hack check -p libafl_qemu -p libafl_qemu_sys --each-feature --clean-per-run \
        --exclude-features=prelude,python,sancov_pcguard_edges,arm,aarch64,i386,be,systemmode,whole_archive,slirp,intel_pt,intel_pt_export_raw \
        --no-dev-deps --features usermode --print-command-list"
    );

    let output = Command::new("sh").arg("-c").arg(the_command).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.trim().lines().collect();

    let all_task_cnt = lines.len() / 2; // one task == two lines
    let task_per_core = all_task_cnt / ci_instances;
    println!("{task_per_core}/{all_task_cnt} tasks assigned to this instance");

    let start = instance_idx * 2 * task_per_core;
    let end = ((instance_idx + 1) * 2 * task_per_core).min(lines.len());
    for &task in &lines[start..end] {
        println!("Running {task}");

        // skip the libafl_jumper no-std case
        if task.contains("utils/libafl_jumper/Cargo.toml")
            && task.contains("--no-default-features")
            && !task.contains("--features")
        {
            continue;
        }

        // run each task, with DOCS_RS override for libafl_frida
        let mut cmd = Command::new("bash");
        cmd.arg("-c");
        if task.contains("libafl_frida") {
            cmd.env("DOCS_RS", "1");
            let task = task.replace("cargo ", "cargo +nightly ");
            cmd.arg(task);
        } else {
            cmd.arg(task);
        }
        let status = cmd.status()?;
        if !status.success() {
            return Err(format!("Command failed (exit code {:?}): {}", status.code(), task).into());
        }
    }

    Ok(())
}
