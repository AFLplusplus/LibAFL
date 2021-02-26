#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case,
         non_upper_case_globals, unused_assignments, unused_mut)]

use std::ptr;

pub const MAP_SIZE: usize = 65536;

extern "C" {
    /// __attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);
    fn LLVMFuzzerInitialize(argc: *mut libc::c_int,
                            argv: *mut *mut *mut libc::c_char) -> libc::c_int;
                            
   /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
   pub fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;
}

static mut orig_argc: libc::c_int = 0;
static mut orig_argv: *mut *mut libc::c_char = ptr::null_mut();
static mut orig_envp: *mut *mut libc::c_char = ptr::null_mut();

pub static mut edges_map: [u8; MAP_SIZE] = [0; MAP_SIZE];
pub static mut cmp_map: [u8; MAP_SIZE] = [0; MAP_SIZE];
pub static mut max_edges_size: usize = 0;

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard(mut guard: *mut u32) {
    let mut pos: u32 = *guard;
    //uint16_t val = __lafl_edges_map[pos] + 1;
    //__lafl_edges_map[pos] = ((uint8_t) val) + (uint8_t) (val >> 8);
    edges_map[pos as usize] = 1 as u8;
}

#[no_mangle]
pub unsafe extern "C" fn __sanitizer_cov_trace_pc_guard_init(mut start: *mut u32, mut stop: *mut u32) {
    if start == stop || *start != 0 { return }
    
    while start < stop {
        max_edges_size += 1;
        *start = (max_edges_size & (MAP_SIZE -1)) as u32;
        start = start.offset(1);
    }
}

unsafe extern "C" fn copy_args_init(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char, mut envp: *mut *mut libc::c_char) {
    orig_argc = argc;
    orig_argv = argv;
    orig_envp = envp;
}

#[no_mangle]
#[link_section = ".init_array"]
static mut p_copy_args_init: Option<unsafe extern "C" fn(_: libc::c_int, _: *mut *mut libc::c_char, _: *mut *mut libc::c_char) -> ()> = Some(copy_args_init);

#[no_mangle]
pub unsafe extern "C" fn afl_libfuzzer_init() -> libc::c_int {
    if Some(LLVMFuzzerInitialize).is_some() {
        LLVMFuzzerInitialize(&mut orig_argc, &mut orig_argv)
    } else {
        0 as libc::c_int
    }
}
