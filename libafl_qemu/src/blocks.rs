use capstone::prelude::*;

use crate::{Emulator, GuestAddr};

pub struct Instruction {
    pub start_addr: GuestAddr,
    pub mnemonic: String,
    pub operands: String,
    pub insn_len: usize,
}

/*
 *  Generating the basic block from it's starting address (pc)
 *  Basic block:
 *  - Starting at pc
 *  - Ending at the first branch/jump/interrupt/call instruction
 *  Output:
 *  - Vector of instructions
 *      - Start address
 *      - mnemonic string
 *      - operand string
 *      - instruction length
 */
pub fn pc2basicblock(
    pc: GuestAddr,
    emu: &Emulator,
    mode: Option<capstone::Mode>,
) -> Result<Vec<Instruction>, String> {
    #[allow(unused_mut)]
    let mut code = {
        #[cfg(emulation_mode = "usermode")]
        unsafe {
            std::slice::from_raw_parts(emu.g2h(pc), 512)
        }
        #[cfg(emulation_mode = "systemmode")]
        &mut [0; 512]
    };
    #[cfg(emulation_mode = "systemmode")]
    unsafe {
        emu.read_mem(pc, code)
    };
    // TODO better fault handling
    if code.iter().all(|&x| x == 0) {
        return Err("Memory region is empty".to_string());
    }

    let mut iaddr = pc;
    let mut block = Vec::<Instruction>::new();

    let mut cs = crate::capstone().detail(true).build().unwrap();
    if let Some(m) = mode {
        cs.set_mode(m).unwrap();
    }

    'disasm: while let Ok(insns) = cs.disasm_count(code, iaddr.into(), 1) {
        if insns.is_empty() {
            break;
        }
        let insn = insns.first().unwrap();
        let insn_detail: InsnDetail = cs.insn_detail(insn).unwrap();
        block.push(Instruction {
            start_addr: insn.address() as GuestAddr,
            mnemonic: insn.mnemonic().unwrap().to_string(),
            operands: insn.op_str().unwrap().to_string(),
            insn_len: insn.len(),
        });
        for detail in insn_detail.groups() {
            match u32::from(detail.0) {
                capstone::InsnGroupType::CS_GRP_BRANCH_RELATIVE
                | capstone::InsnGroupType::CS_GRP_CALL
                | capstone::InsnGroupType::CS_GRP_INT
                | capstone::InsnGroupType::CS_GRP_INVALID
                | capstone::InsnGroupType::CS_GRP_IRET
                | capstone::InsnGroupType::CS_GRP_JUMP
                | capstone::InsnGroupType::CS_GRP_PRIVILEGE
                | capstone::InsnGroupType::CS_GRP_RET => {
                    break 'disasm;
                }
                _ => {}
            }
        }

        iaddr += insn.bytes().len() as GuestAddr;

        #[cfg(emulation_mode = "usermode")]
        unsafe {
            code = std::slice::from_raw_parts(emu.g2h(iaddr), 512);
        }
        #[cfg(emulation_mode = "systemmode")]
        unsafe {
            emu.read_mem(iaddr, code);
        }
        // TODO better fault handling
        if code.iter().all(|&x| x == 0) {
            return Err("Memory region is empty".to_string());
        }
    }

    Ok(block)
}
