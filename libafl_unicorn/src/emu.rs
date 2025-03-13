use capstone::{
    Capstone,
    arch::{self, BuildsCapstone, BuildsCapstoneSyntax},
};
pub use libafl_targets::{EDGES_MAP, EDGES_MAP_PTR};
use unicorn_engine::{
    RegisterARM, RegisterARM64, RegisterX86, Unicorn,
    unicorn_const::{Arch, Permission},
};

use crate::helper::get_stack_pointer;
// TODO: For some reason, the compiled program start by substracting 0x10 to SP

pub fn memory_dump(emu: &Unicorn<()>, len: u64) {
    let sp = get_stack_pointer(emu);
    for i in 0..len {
        let pos = sp + i * 4 - len * 4;

        let data = emu.mem_read_as_vec(pos, 4).unwrap();

        log::debug!(
            "{:X}:\t {:02X} {:02X} {:02X} {:02X}  {:08b} {:08b} {:08b} {:08b}",
            pos,
            data[0],
            data[1],
            data[2],
            data[3],
            data[0],
            data[1],
            data[2],
            data[3]
        );
    }
}

// Display some register values and disassemble the instructions around the program counter
// address. The thumb_mode parameter is only taken into account when the architecture used is ARM.
pub fn debug_print(emu: &Unicorn<()>, thumb_mode: bool) {
    log::debug!("Status when crash happened:");

    let pc = emu.pc_read().unwrap();

    log::debug!("PC: {:X}", pc);
    let arch = emu.get_arch();
    match arch {
        Arch::ARM => {
            log::debug!("SP: {:X}", emu.reg_read(RegisterARM::SP).unwrap());
            log::debug!("R0: {:X}", emu.reg_read(RegisterARM::R0).unwrap());
            log::debug!("R1: {:X}", emu.reg_read(RegisterARM::R1).unwrap());
            log::debug!("R2: {:X}", emu.reg_read(RegisterARM::R2).unwrap());
            log::debug!("R3: {:X}", emu.reg_read(RegisterARM::R3).unwrap());
        }
        Arch::ARM64 => {
            log::debug!("SP: {:X}", emu.reg_read(RegisterARM64::SP).unwrap());
            log::debug!("X0: {:X}", emu.reg_read(RegisterARM64::X0).unwrap());
            log::debug!("X1: {:X}", emu.reg_read(RegisterARM64::X1).unwrap());
            log::debug!("X2: {:X}", emu.reg_read(RegisterARM64::X2).unwrap());
            log::debug!("X3: {:X}", emu.reg_read(RegisterARM64::X3).unwrap());
        }
        Arch::X86 => {
            log::debug!("ESP: {:X}", emu.reg_read(RegisterX86::ESP).unwrap());
            log::debug!("RAX: {:X}", emu.reg_read(RegisterX86::RAX).unwrap());
            log::debug!("RCX: {:X}", emu.reg_read(RegisterX86::RCX).unwrap());
            log::debug!("RDX: {:X}", emu.reg_read(RegisterX86::RDX).unwrap());
            log::debug!("RPB: {:X}", emu.reg_read(RegisterX86::RBP).unwrap());
            log::debug!("RSP: {:X}", emu.reg_read(RegisterX86::RSP).unwrap());
        }
        _ => {}
    }

    // Provide disassembly at instant of crash
    let regions = emu.mem_regions().expect("Could not get memory regions");
    for region in regions {
        if region.perms.contains(Permission::EXEC) && pc >= region.begin && pc <= region.end {
            let mut begin = pc - 32;
            let mut end = pc + 32;
            if begin < region.begin {
                begin = region.begin;
            }
            if end > region.end {
                end = region.end;
            }

            let bytes = emu
                .mem_read_as_vec(begin, (end - begin) as usize)
                .expect("Could not get program code");
            let cs = match emu.get_arch() {
                Arch::ARM => Capstone::new()
                    .arm()
                    .mode(match thumb_mode {
                        true => arch::arm::ArchMode::Thumb,
                        false => arch::arm::ArchMode::Arm,
                    })
                    .detail(true)
                    .build()
                    .expect("Failed to create Capstone object"),
                Arch::ARM64 => Capstone::new()
                    .arm64()
                    .mode(arch::arm64::ArchMode::Arm)
                    .detail(true)
                    .build()
                    .expect("Failed to create Capstone object"),

                _ => Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .syntax(arch::x86::ArchSyntax::Intel)
                    .detail(true)
                    .build()
                    .expect("Failed to create Capstone object"),
            };
            let insns = cs.disasm_all(&bytes, begin).expect("Failed to disassemble");

            if !insns.is_empty() {
                log::debug!("Code dump: [0x{begin:x} -> 0x{end:x}]");
            } else {
                log::debug!("No disassembly available at PC: 0x{pc:x}");
            }

            for i in insns.as_ref() {
                log::debug!("{}", i);
            }
        }
    }
}
