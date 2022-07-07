// adapted from libnyx::FFI, change the C-style FFI function into pure rust

use libnyx::NyxConfig;
use libnyx::NyxProcess;
use libnyx::NyxReturnValue;
use libnyx::ffi::{NYX_ABORT,NYX_CRASH,NYX_HPRINTF};



pub fn nyx_load_config(sharedir_r_str: &str) -> Option<NyxConfig>{

    let cfg: NyxConfig = match NyxConfig::load(sharedir_r_str){
        Ok(x) => x,
        Err(msg) => {
            println!("[!] libnyx config reader error: {}", msg);
            return None
        }
    };

    Some(cfg)
}

pub fn nyx_print_config(config: NyxConfig) {
        let cfg = config;
        println!("{}", cfg);
}

fn nyx_process_start(sharedir_r_str: &str, workdir_r_str: &str, worker_id: u32, cpu_id: u32, create_snapshot: bool, input_buffer_size: Option<u32>, input_buffer_write_protection: bool) -> Option<NyxProcess> {

    
    match NyxProcess::process_start(sharedir_r_str, workdir_r_str, worker_id, cpu_id, create_snapshot, input_buffer_size, input_buffer_write_protection) {
        Ok(x) => {Some(x)}
        Err(msg) => {
            println!("[!] libnyx failed to initialize QEMU-Nyx: {}", msg);
            None
        },
    }
}


pub fn nyx_new(sharedir: &str, workdir: &str, cpu_id: u32, input_buffer_size: u32, input_buffer_write_protection: bool) -> Option<NyxProcess> {
    nyx_process_start(sharedir, workdir, 0, cpu_id, false, Some(input_buffer_size), input_buffer_write_protection)
}



pub fn nyx_new_parent(sharedir: &str, workdir: &str, cpu_id: u32, input_buffer_size: u32, input_buffer_write_protection: bool) -> Option<NyxProcess> {
    nyx_process_start(sharedir, workdir, 0, cpu_id, true, Some(input_buffer_size), input_buffer_write_protection)
}


pub fn nyx_new_child(sharedir: &str, workdir: &str, cpu_id: u32, worker_id: u32) -> Option<NyxProcess> {
    if worker_id == 0 {
        println!("[!] libnyx failed -> worker_id=0 cannot be used for child processes");
        return None
    }
    else{
        nyx_process_start(sharedir, workdir, worker_id, cpu_id, true, None, false)
    }
}
 


pub fn nyx_get_aux_buffer(nyx_process: NyxProcess)-> *mut u8 {

        return nyx_process.aux_buffer_as_mut_ptr();
}


pub fn nyx_get_input_buffer(mut nyx_process: NyxProcess) -> *mut u8 {

        return nyx_process.input_buffer_mut().as_mut_ptr();
}


pub fn nyx_get_bitmap_buffer(mut nyx_process: NyxProcess) -> *mut u8 {

        return nyx_process.bitmap_buffer_mut().as_mut_ptr();
}


pub fn nyx_get_bitmap_buffer_size(nyx_process: NyxProcess) -> usize {
        //return nyx_process.process.bitmap.len();
        return nyx_process.bitmap_buffer_size();
}


pub fn nyx_shutdown(mut nyx_process:NyxProcess) {

        nyx_process.shutdown();
}


pub fn nyx_option_set_reload_mode(mut nyx_process:NyxProcess, enable: bool) {

        nyx_process.option_set_reload_mode(enable);
}


pub fn nyx_option_set_timeout(mut nyx_process: NyxProcess, timeout_sec: u8, timeout_usec: u32) {

        nyx_process.option_set_timeout(timeout_sec, timeout_usec);
}


pub fn nyx_option_apply(mut nyx_process: NyxProcess) {

        nyx_process.option_apply();
}


pub fn nyx_exec(mut nyx_process: NyxProcess) -> NyxReturnValue {
    

        nyx_process.exec()
}


pub fn nyx_set_afl_input(mut nyx_process: NyxProcess, buffer: *mut u8, size: u32) {

        nyx_process.set_input_ptr(buffer, size);
}



pub fn nyx_print_aux_buffer(nyx_process: NyxProcess) {

        print!("{}", format!("{:#?}", nyx_process.process.aux.result));


        match nyx_process.process.aux.result.exec_result_code {
            NYX_CRASH | NYX_ABORT | NYX_HPRINTF => {
                println!("{}", std::str::from_utf8(&nyx_process.process.aux.misc.data).unwrap());
            },
            _ => {},
        }
}


pub fn nyx_get_aux_string(nyx_process: NyxProcess, buffer: *mut u8, size: u32) -> u32 {

    unsafe{

        let len = std::cmp::min( nyx_process.process.aux.misc.len as usize, size as usize);
        std::ptr::copy(nyx_process.process.aux.misc.data.as_mut_ptr(), buffer, len);
        len as u32
    }
}


