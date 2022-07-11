// adapted from libnyx::FFI, change the C-style FFI function into pure rust

use libnyx::ffi::{nyx_set_afl_input, NYX_ABORT, NYX_CRASH, NYX_HPRINTF};
use libnyx::NyxConfig;
pub use libnyx::NyxProcess;

pub type NyxResult<T> = Result<T, String>;

pub fn nyx_load_config(sharedir_r_str: &str) -> NyxResult<NyxConfig> {
    NyxConfig::load(sharedir_r_str)
}

pub fn nyx_print_config(config: NyxConfig) {
    let cfg = config;
    println!("{}", cfg);
}

fn nyx_process_start(
    sharedir_r_str: &str,
    workdir_r_str: &str,
    worker_id: u32,
    cpu_id: u32,
    create_snapshot: bool,
    input_buffer_size: Option<u32>,
    input_buffer_write_protection: bool,
) -> NyxResult<NyxProcess> {
    NyxProcess::process_start(
        sharedir_r_str,
        workdir_r_str,
        worker_id,
        cpu_id,
        create_snapshot,
        input_buffer_size,
        input_buffer_write_protection,
    )
}

pub fn nyx_new(
    sharedir: &str,
    workdir: &str,
    cpu_id: u32,
    input_buffer_size: u32,
    input_buffer_write_protection: bool,
) -> NyxResult<NyxProcess> {
    nyx_process_start(
        sharedir,
        workdir,
        0,
        cpu_id,
        false,
        Some(input_buffer_size),
        input_buffer_write_protection,
    )
}

pub fn nyx_new_parent(
    sharedir: &str,
    workdir: &str,
    cpu_id: u32,
    input_buffer_size: u32,
    input_buffer_write_protection: bool,
) -> NyxResult<NyxProcess> {
    nyx_process_start(
        sharedir,
        workdir,
        0,
        cpu_id,
        true,
        Some(input_buffer_size),
        input_buffer_write_protection,
    )
}

pub fn nyx_new_child(
    sharedir: &str,
    workdir: &str,
    cpu_id: u32,
    worker_id: u32,
) -> NyxResult<NyxProcess> {
    if worker_id == 0 {
        let msg = "[!] libnyx failed -> worker_id=0 cannot be used for child processes";
        return Err(msg.to_string());
    }
    nyx_process_start(sharedir, workdir, worker_id, cpu_id, true, None, false)
}

pub fn nyx_print_aux_buffer(nyx_process: &mut NyxProcess) {
    print!("{}", format!("{:#?}", nyx_process.process.aux.result));

    match nyx_process.process.aux.result.exec_result_code {
        NYX_CRASH | NYX_ABORT | NYX_HPRINTF => {
            println!(
                "{}",
                std::str::from_utf8(&nyx_process.process.aux.misc.data).unwrap()
            );
        }
        _ => {}
    }
}

pub fn nyx_get_aux_string(nyx_process: &mut NyxProcess, buffer: *mut u8, size: u32) -> u32 {
    unsafe {
        let len = std::cmp::min(nyx_process.process.aux.misc.len as usize, size as usize);
        std::ptr::copy(nyx_process.process.aux.misc.data.as_mut_ptr(), buffer, len);
        len as u32
    }
}
