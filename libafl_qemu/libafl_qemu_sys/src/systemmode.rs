use paste::paste;

use crate::extern_c_checked;

extern_c_checked! {
    pub fn qemu_init(argc: i32, argv: *const *const u8);

    pub fn vm_start();
    pub fn qemu_main_loop();
    pub fn qemu_cleanup();
}
