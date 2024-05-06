use paste::paste;

use crate::{extern_c_checked, CPUStatePtr, GuestPhysAddr};

extern_c_checked! {
    pub fn qemu_init(argc: i32, argv: *const *const u8, envp: *const *const u8);

    pub fn vm_start();
    pub fn qemu_main_loop();
    pub fn qemu_cleanup();

    pub fn libafl_save_qemu_snapshot(name: *const u8, sync: bool);
    pub fn libafl_load_qemu_snapshot(name: *const u8, sync: bool);

    pub fn libafl_qemu_current_paging_id(cpu: CPUStatePtr) -> GuestPhysAddr;
}
