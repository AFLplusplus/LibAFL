use core::ffi::{CStr, c_char, c_int, c_void};

use libc::{SIGABRT, pid_t};

use crate::{
    GuestAddr, asan_swap,
    symbols::{Function, FunctionPointer},
};

#[derive(Debug)]
struct FunctionGetpid;

impl Function for FunctionGetpid {
    type Func = unsafe extern "C" fn() -> pid_t;
    const NAME: &'static CStr = c"getpid";
}

#[derive(Debug)]
struct FunctionKill;

impl Function for FunctionKill {
    type Func = unsafe extern "C" fn(pid_t, c_int) -> c_int;
    const NAME: &'static CStr = c"kill";
}

#[derive(Debug)]
struct FunctionExit;

impl Function for FunctionExit {
    type Func = unsafe extern "C" fn(c_int) -> !;
    const NAME: &'static CStr = c"_exit";
}

unsafe extern "C" {
    fn asan_sym(name: *const c_char) -> *const c_void;
}

pub fn abort() -> ! {
    let getpid_addr = unsafe { asan_sym(FunctionGetpid::NAME.as_ptr() as *const c_char) };
    let fn_getpid = FunctionGetpid::as_ptr(getpid_addr as GuestAddr).unwrap();

    let kill_addr = unsafe { asan_sym(FunctionKill::NAME.as_ptr() as *const c_char) };
    let fn_kill = FunctionKill::as_ptr(kill_addr as GuestAddr).unwrap();

    unsafe { asan_swap(false) };
    let pid = unsafe { fn_getpid() };
    unsafe { fn_kill(pid, SIGABRT) };
    unreachable!();
}

pub fn exit(status: c_int) -> ! {
    let exit_addr = unsafe { asan_sym(FunctionExit::NAME.as_ptr() as *const c_char) };
    let fn_exit = FunctionExit::as_ptr(exit_addr as GuestAddr).unwrap();
    unsafe { asan_swap(false) };
    unsafe { fn_exit(status) };
}
