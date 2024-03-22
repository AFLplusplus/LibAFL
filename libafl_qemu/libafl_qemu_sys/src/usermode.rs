use core::ffi::c_void;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use paste::paste;
use strum_macros::EnumIter;

use crate::{extern_c_checked, GuestAddr, MapInfo};

extern_c_checked! {
    pub fn qemu_user_init(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32;

    pub fn libafl_qemu_run() -> i32;

    pub fn libafl_load_addr() -> u64;
    pub fn libafl_get_brk() -> u64;
    pub fn libafl_set_brk(brk: u64) -> u64;

    pub fn read_self_maps() -> *const c_void;
    pub fn free_self_maps(map_info: *const c_void);

    pub fn libafl_maps_next(map_info: *const c_void, ret: *mut MapInfo) -> *const c_void;

    pub static exec_path: *const u8;
    pub static guest_base: usize;
    pub static mut mmap_next_start: GuestAddr;

    pub static mut libafl_dump_core_hook: unsafe extern "C" fn(i32);
    pub static mut libafl_force_dfl: i32;
}

#[derive(IntoPrimitive, TryFromPrimitive, Debug, Clone, Copy, EnumIter, PartialEq, Eq)]
#[repr(i32)]
pub enum VerifyAccess {
    Read = libc::PROT_READ,
    Write = libc::PROT_READ | libc::PROT_WRITE,
}
