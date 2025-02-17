use unicorn_engine::{unicorn_const::Arch, RegisterARM, RegisterARM64, RegisterX86};

pub fn get_stack_pointer(emu: &unicorn_engine::Unicorn<()>) -> u64 {
    match emu.get_arch() {
        Arch::ARM => emu.reg_read(RegisterARM::SP).unwrap(),
        Arch::ARM64 => emu.reg_read(RegisterARM64::SP).unwrap(),
        Arch::X86 => emu.reg_read(RegisterX86::ESP).unwrap(),
        _ => 0,
    }
}
