use capstone::{
    arch::{self, BuildsCapstone, BuildsCapstoneSyntax},
    Capstone,
};
pub use libafl_targets::{EDGES_MAP, EDGES_MAP_PTR};
use unicorn_engine::{
    unicorn_const::{uc_error, Arch, Permission},
    RegisterARM, RegisterARM64, RegisterX86, Unicorn,
};

use crate::helper::get_stack_pointer;
// TODO: For some reason, the compiled program start by substracting 0x10 to SP

pub fn memory_dump(emu: &Unicorn<()>, len: u64) {
    let sp = get_stack_pointer(emu);
    for i in 0..len {
        let pos = sp + i * 4 - len * 4;

        let data = emu.mem_read_as_vec(pos, 4).unwrap();

        println!(
            "{:X}:\t {:02X} {:02X} {:02X} {:02X}  {:08b} {:08b} {:08b} {:08b}",
            pos, data[0], data[1], data[2], data[3], data[0], data[1], data[2], data[3]
        );
    }
}

pub fn debug_print(emu: &Unicorn<()>, err: uc_error) {
    println!("Status when crash happened:");

    let pc = emu.pc_read().unwrap();

    println!("PC: {:X}", pc);
    let arch = emu.get_arch();

    match arch {
        Arch::ARM => {
            println!("SP: {:X}", emu.reg_read(RegisterARM::SP).unwrap());
            println!("R0: {:X}", emu.reg_read(RegisterARM::R0).unwrap());
            println!("R1: {:X}", emu.reg_read(RegisterARM::R1).unwrap());
            println!("R2: {:X}", emu.reg_read(RegisterARM::R2).unwrap());
            println!("R3: {:X}", emu.reg_read(RegisterARM::R3).unwrap());
        }
        Arch::ARM64 => {
            println!("SP: {:X}", emu.reg_read(RegisterARM64::SP).unwrap());
            println!("X0: {:X}", emu.reg_read(RegisterARM64::X0).unwrap());
            println!("X1: {:X}", emu.reg_read(RegisterARM64::X1).unwrap());
            println!("X2: {:X}", emu.reg_read(RegisterARM64::X2).unwrap());
            println!("X3: {:X}", emu.reg_read(RegisterARM64::X3).unwrap());
        }
        Arch::X86 => {
            println!("ESP: {:X}", emu.reg_read(RegisterX86::ESP).unwrap());
            println!("RAX: {:X}", emu.reg_read(RegisterX86::RAX).unwrap());
            println!("RCX: {:X}", emu.reg_read(RegisterX86::RCX).unwrap());
            println!("RDX: {:X}", emu.reg_read(RegisterX86::RDX).unwrap());
            println!("RPB: {:X}", emu.reg_read(RegisterX86::RBP).unwrap());
            println!("RSP: {:X}", emu.reg_read(RegisterX86::RSP).unwrap());
        }
        _ => {}
    }

    // Provide disassembly at instant of crash
    let regions = emu.mem_regions().expect("Could not get memory regions");
    for i in 0..regions.len() {
        if regions[i].perms.contains(Permission::EXEC) {
            if pc >= regions[i].begin && pc <= regions[i].end {
                let mut begin = pc - 32;
                let mut end = pc + 32;
                if begin < regions[i].begin {
                    begin = regions[i].begin;
                }
                if end > regions[i].end {
                    end = regions[i].end;
                }

                let bytes = emu
                    .mem_read_as_vec(begin, (end - begin) as usize)
                    .expect("Could not get program code");
                let cs = match emu.get_arch() {
                    Arch::ARM => Capstone::new()
                        .arm()
                        .mode(arch::arm::ArchMode::Thumb)
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
                    println!("Code dump: [0x{begin:x} -> 0x{end:x}]");
                } else {
                    println!("No disassembly available at PC: 0x{pc:x}");
                }

                for i in insns.as_ref() {
                    println!("{}", i);
                }
            }
        }
    }
}
