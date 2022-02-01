//! Functionality for [`frida`](https://frida.re)-based binary-only `CmpLog`.
//! With it, a fuzzer can collect feedback about each compare that happenned in the target
//! This allows the fuzzer to potentially solve the compares, if a compare value is directly
//! related to the input.
//! Read the [`RedQueen`](https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/) paper for the general concepts.
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi};
use libafl::{
    inputs::{HasTargetBytes, Input},
    Error,
};
use libafl_targets;
use libafl_targets::CMPLOG_MAP_W;
use rangemap::RangeMap;
use std::ffi::c_void;

use crate::helper::FridaRuntime;
extern "C" {
    /// Tracks cmplog instructions
    pub fn __libafl_targets_cmplog_instructions(k: u64, shape: u8, arg1: u64, arg2: u64);
}

#[cfg(target_arch = "aarch64")]
use frida_gum::{
    instruction_writer::{Aarch64Register, IndexMode, InstructionWriter},
    stalker::StalkerOutput,
};

#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
use crate::utils::{instruction_width, writer_register};

#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
/// Speciial CmpLog Cases for `aarch64`
#[derive(Debug)]
pub enum SpecialCmpLogCase {
    /// Test bit and branch if zero
    Tbz,
    /// Test bit and branch if not zero
    Tbnz,
}

#[cfg(target_arch = "aarch64")]
use capstone::{
    arch::{arm64::Arm64OperandType, ArchOperand::Arm64Operand},
    Capstone, Insn,
};

/// The type of an operand loggged during `CmpLog`
#[derive(Debug)]
#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
pub enum CmplogOperandType {
    /// A Register
    Regid(capstone::RegId),
    /// An immediate value
    Imm(u64),
    /// A constant immediate value
    Cimm(u64),
    /// A memory operand
    Mem(capstone::RegId, capstone::RegId, i32, u32),
}

/// `Frida`-based binary-only innstrumentation that logs compares to the fuzzer
/// `LibAFL` can use this knowledge for powerful mutations.
#[derive(Debug)]
pub struct CmpLogRuntime {
    ops_save_register_and_blr_to_populate: Option<Box<[u8]>>,
    ops_handle_tbz_masking: Option<Box<[u8]>>,
    ops_handle_tbnz_masking: Option<Box<[u8]>>,
}

impl FridaRuntime for CmpLogRuntime {
    /// Initialize this `CmpLog` runtime.
    /// This will generate the instrumentation blobs for the current arch.
    fn init(
        &mut self,
        _gum: &frida_gum::Gum,
        _ranges: &RangeMap<usize, (u16, String)>,
        _modules_to_instrument: &[&str],
    ) {
        self.generate_instrumentation_blobs();
    }

    fn pre_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}

impl CmpLogRuntime {
    /// Create a new [`CmpLogRuntime`]
    #[must_use]
    pub fn new() -> CmpLogRuntime {
        Self {
            ops_save_register_and_blr_to_populate: None,
            ops_handle_tbz_masking: None,
            ops_handle_tbnz_masking: None,
        }
    }

    /// Call the external function that populates the `cmplog_map` with the relevant values
    #[allow(clippy::unused_self)]
    extern "C" fn populate_lists(&mut self, op1: u64, op2: u64, retaddr: u64) {
        // println!(
        //     "entered populate_lists with: {:#02x}, {:#02x}, {:#02x}",
        //     op1, op2, retaddr
        // );
        let mut k = (retaddr >> 4) ^ (retaddr << 8);

        k &= (CMPLOG_MAP_W as u64) - 1;

        unsafe {
            __libafl_targets_cmplog_instructions(k, 8, op1, op2);
        }
    }

    /// Generate the instrumentation blobs for the current arch.
    #[allow(clippy::similar_names)]
    fn generate_instrumentation_blobs(&mut self) {
        macro_rules! blr_to_populate {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x2, x3, [sp, #-0x10]!
                ; stp x4, x5, [sp, #-0x10]!
                ; stp x6, x7, [sp, #-0x10]!
                ; stp x8, x9, [sp, #-0x10]!
                ; stp x10, x11, [sp, #-0x10]!
                ; stp x12, x13, [sp, #-0x10]!
                ; stp x14, x15, [sp, #-0x10]!
                ; stp x16, x17, [sp, #-0x10]!
                ; stp x18, x19, [sp, #-0x10]!
                ; stp x20, x21, [sp, #-0x10]!
                ; stp x22, x23, [sp, #-0x10]!
                ; stp x24, x25, [sp, #-0x10]!
                ; stp x26, x27, [sp, #-0x10]!
                ; stp x28, x29, [sp, #-0x10]!
                ; stp x30, xzr, [sp, #-0x10]!
                ; .dword 0xd53b4218u32 as i32 // mrs x24, nzcv
                // jump to rust based population of the lists
                ; mov x2, x0
                ; adr x3, >done
                ; ldr x4, >populate_lists
                ; ldr x0, >self_addr
                ; blr x4
                // restore the reg state before returning to the caller
                ; .dword 0xd51b4218u32 as i32 // msr nzcv, x24
                ; ldp x30, xzr, [sp], #0x10
                ; ldp x28, x29, [sp], #0x10
                ; ldp x26, x27, [sp], #0x10
                ; ldp x24, x25, [sp], #0x10
                ; ldp x22, x23, [sp], #0x10
                ; ldp x20, x21, [sp], #0x10
                ; ldp x18, x19, [sp], #0x10
                ; ldp x16, x17, [sp], #0x10
                ; ldp x14, x15, [sp], #0x10
                ; ldp x12, x13, [sp], #0x10
                ; ldp x10, x11, [sp], #0x10
                ; ldp x8, x9, [sp], #0x10
                ; ldp x6, x7, [sp], #0x10
                ; ldp x4, x5, [sp], #0x10
                ; ldp x2, x3, [sp], #0x10
                ; b >done
                ; self_addr:
                ; .qword self as *mut _  as *mut c_void as i64
                ; populate_lists:
                ; .qword  CmpLogRuntime::populate_lists as *mut c_void as i64
                ; done:
            );};
        }

        // ldp/stp is more efficient than str/ldr so we use them instead.
        macro_rules! tbz_masking {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x5, x5, [sp, #-0x10]!
                ; mov x5, #1
                ; lsl x5, x5, x1
                ; eor x5, x5, #255
                ; orr x1, x0, x5
                ; ldp x5, x5, [sp], #0x10
            );};
        }

        macro_rules! tbnz_masking {
            ($ops:ident) => {dynasm!($ops
                ; .arch aarch64
                ; stp x5, x5, [sp, #-0x10]!
                ; mov x5, #1
                ; lsl x5, x5, x1
                ; orr x1, x0, x5
                ; ldp x5, x5, [sp], #0x10
            );};

        }

        let mut ops_handle_tbz_masking =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        tbz_masking!(ops_handle_tbz_masking);

        let mut ops_handle_tbnz_masking =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        tbnz_masking!(ops_handle_tbnz_masking);

        let mut ops_save_register_and_blr_to_populate =
            dynasmrt::VecAssembler::<dynasmrt::aarch64::Aarch64Relocation>::new(0);
        blr_to_populate!(ops_save_register_and_blr_to_populate);

        self.ops_handle_tbz_masking = Some(
            ops_handle_tbz_masking
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );

        self.ops_handle_tbnz_masking = Some(
            ops_handle_tbnz_masking
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );

        self.ops_save_register_and_blr_to_populate = Some(
            ops_save_register_and_blr_to_populate
                .finalize()
                .unwrap()
                .into_boxed_slice(),
        );
    }

    /// Get the blob which saves the context, jumps to the populate function and restores the context
    #[inline]
    #[must_use]
    pub fn ops_save_register_and_blr_to_populate(&self) -> &[u8] {
        self.ops_save_register_and_blr_to_populate.as_ref().unwrap()
    }

    /// Get the blob which handles the tbz opcode masking
    #[inline]
    #[must_use]
    pub fn ops_handle_tbz_masking(&self) -> &[u8] {
        self.ops_handle_tbz_masking.as_ref().unwrap()
    }

    /// Get the blob which handles the tbnz opcode masking
    #[inline]
    #[must_use]
    pub fn ops_handle_tbnz_masking(&self) -> &[u8] {
        self.ops_handle_tbnz_masking.as_ref().unwrap()
    }

    /// Emit the instrumentation code which is responsible for opernads value extraction and cmplog map population
    #[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
    #[inline]
    pub fn emit_comparison_handling(
        &self,
        _address: u64,
        output: &StalkerOutput,
        op1: CmplogOperandType,
        op2: CmplogOperandType,
        special_case: Option<SpecialCmpLogCase>,
    ) {
        let writer = output.writer();

        // Preserve x0, x1:
        writer.put_stp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            -(16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i32) as i64,
            IndexMode::PreAdjust,
        );

        // make sure operand1 value is saved into x0
        match op1 {
            CmplogOperandType::Imm(value) | CmplogOperandType::Cimm(value) => {
                writer.put_ldr_reg_u64(Aarch64Register::X0, value);
            }
            CmplogOperandType::Regid(reg) => {
                let reg = writer_register(reg);
                match reg {
                    Aarch64Register::X0 | Aarch64Register::W0 => {}
                    Aarch64Register::X1 | Aarch64Register::W1 => {
                        writer.put_mov_reg_reg(Aarch64Register::X0, Aarch64Register::X1);
                    }
                    _ => {
                        if !writer.put_mov_reg_reg(Aarch64Register::X0, reg) {
                            writer.put_mov_reg_reg(Aarch64Register::W0, reg);
                        }
                    }
                }
            }
            CmplogOperandType::Mem(basereg, indexreg, displacement, _width) => {
                let basereg = writer_register(basereg);
                let indexreg = if indexreg.0 != 0 {
                    Some(writer_register(indexreg))
                } else {
                    None
                };

                // calculate base+index+displacment into x0
                let displacement = displacement
                    + if basereg == Aarch64Register::Sp {
                        16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i32
                    } else {
                        0
                    };

                if indexreg.is_some() {
                    if let Some(indexreg) = indexreg {
                        writer.put_add_reg_reg_reg(Aarch64Register::X0, basereg, indexreg);
                    }
                } else {
                    match basereg {
                        Aarch64Register::X0 | Aarch64Register::W0 => {}
                        Aarch64Register::X1 | Aarch64Register::W1 => {
                            writer.put_mov_reg_reg(Aarch64Register::X0, Aarch64Register::X1);
                        }
                        _ => {
                            if !writer.put_mov_reg_reg(Aarch64Register::X0, basereg) {
                                writer.put_mov_reg_reg(Aarch64Register::W0, basereg);
                            }
                        }
                    }
                }

                //add displacement
                writer.put_add_reg_reg_imm(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    displacement as u64,
                );

                //deref into x0 to get the real value
                writer.put_ldr_reg_reg_offset(Aarch64Register::X0, Aarch64Register::X0, 0u64);
            }
        }

        // make sure operand2 value is saved into x1
        match op2 {
            CmplogOperandType::Imm(value) | CmplogOperandType::Cimm(value) => {
                writer.put_ldr_reg_u64(Aarch64Register::X1, value);
                match special_case {
                    Some(inst) => match inst {
                        SpecialCmpLogCase::Tbz => {
                            writer.put_bytes(&self.ops_handle_tbz_masking());
                        }
                        SpecialCmpLogCase::Tbnz => {
                            writer.put_bytes(&self.ops_handle_tbnz_masking());
                        }
                    },
                    None => (),
                }
            }
            CmplogOperandType::Regid(reg) => {
                let reg = writer_register(reg);
                match reg {
                    Aarch64Register::X1 | Aarch64Register::W1 => {}
                    Aarch64Register::X0 | Aarch64Register::W0 => {
                        writer.put_ldr_reg_reg_offset(
                            Aarch64Register::X1,
                            Aarch64Register::Sp,
                            0u64,
                        );
                    }
                    _ => {
                        if !writer.put_mov_reg_reg(Aarch64Register::X1, reg) {
                            writer.put_mov_reg_reg(Aarch64Register::W1, reg);
                        }
                    }
                }
            }
            CmplogOperandType::Mem(basereg, indexreg, displacement, _width) => {
                let basereg = writer_register(basereg);
                let indexreg = if indexreg.0 != 0 {
                    Some(writer_register(indexreg))
                } else {
                    None
                };

                // calculate base+index+displacment into x1
                let displacement = displacement
                    + if basereg == Aarch64Register::Sp {
                        16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i32
                    } else {
                        0
                    };

                if indexreg.is_some() {
                    if let Some(indexreg) = indexreg {
                        match indexreg {
                            Aarch64Register::X0 | Aarch64Register::W0 => {
                                match basereg {
                                    Aarch64Register::X1 | Aarch64Register::W1 => {
                                        // x0 is overwrittern indexreg by op1 value.
                                        // x1 is basereg

                                        // Preserve x2, x3:
                                        writer.put_stp_reg_reg_reg_offset(
                                            Aarch64Register::X2,
                                            Aarch64Register::X3,
                                            Aarch64Register::Sp,
                                            -(16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i32) as i64,
                                            IndexMode::PreAdjust,
                                        );

                                        //reload indexreg to x2
                                        writer.put_ldr_reg_reg_offset(
                                            Aarch64Register::X2,
                                            Aarch64Register::Sp,
                                            0u64,
                                        );
                                        //add them into basereg==x1
                                        writer.put_add_reg_reg_reg(
                                            basereg,
                                            basereg,
                                            Aarch64Register::X2,
                                        );

                                        // Restore x2, x3
                                        assert!(writer.put_ldp_reg_reg_reg_offset(
                                            Aarch64Register::X2,
                                            Aarch64Register::X3,
                                            Aarch64Register::Sp,
                                            16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i64,
                                            IndexMode::PostAdjust,
                                        ));
                                    }
                                    _ => {
                                        // x0 is overwrittern indexreg by op1 value.
                                        // basereg is not x1 nor x0

                                        //reload indexreg to x1
                                        writer.put_ldr_reg_reg_offset(
                                            Aarch64Register::X1,
                                            Aarch64Register::Sp,
                                            0u64,
                                        );
                                        //add basereg into indexreg==x1
                                        writer.put_add_reg_reg_reg(
                                            Aarch64Register::X1,
                                            basereg,
                                            Aarch64Register::X1,
                                        );
                                    }
                                }
                            }
                            Aarch64Register::X1 | Aarch64Register::W1 => {
                                match basereg {
                                    Aarch64Register::X0 | Aarch64Register::W0 => {
                                        // x0 is overwrittern basereg by op1 value.
                                        // x1 is indexreg

                                        // Preserve x2, x3:
                                        writer.put_stp_reg_reg_reg_offset(
                                            Aarch64Register::X2,
                                            Aarch64Register::X3,
                                            Aarch64Register::Sp,
                                            -(16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i32) as i64,
                                            IndexMode::PreAdjust,
                                        );

                                        //reload basereg to x2
                                        writer.put_ldr_reg_reg_offset(
                                            Aarch64Register::X2,
                                            Aarch64Register::Sp,
                                            0u64,
                                        );
                                        //add basereg into indexreg==x1
                                        writer.put_add_reg_reg_reg(
                                            indexreg,
                                            Aarch64Register::X2,
                                            indexreg,
                                        );

                                        // Restore x2, x3
                                        assert!(writer.put_ldp_reg_reg_reg_offset(
                                            Aarch64Register::X2,
                                            Aarch64Register::X3,
                                            Aarch64Register::Sp,
                                            16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i64,
                                            IndexMode::PostAdjust,
                                        ));
                                    }
                                    _ => {
                                        // indexreg is x1
                                        // basereg is not x0 and not x1

                                        //add them into x1
                                        writer.put_add_reg_reg_reg(indexreg, basereg, indexreg);
                                    }
                                }
                            }
                            _ => {
                                match basereg {
                                    Aarch64Register::X0 | Aarch64Register::W0 => {
                                        //basereg is overwrittern by op1 value
                                        //index reg is not x0 nor x1

                                        //reload basereg to x1
                                        writer.put_ldr_reg_reg_offset(
                                            Aarch64Register::X1,
                                            Aarch64Register::Sp,
                                            0u64,
                                        );
                                        //add indexreg to basereg==x1
                                        writer.put_add_reg_reg_reg(
                                            Aarch64Register::X1,
                                            Aarch64Register::X1,
                                            indexreg,
                                        );
                                    }
                                    _ => {
                                        //basereg is not x0, can be x1
                                        //index reg is not x0 nor x1

                                        //add them into x1
                                        writer.put_add_reg_reg_reg(
                                            Aarch64Register::X1,
                                            basereg,
                                            indexreg,
                                        );
                                    }
                                }
                            }
                        }
                    }
                } else {
                    match basereg {
                        Aarch64Register::X1 | Aarch64Register::W1 => {}
                        Aarch64Register::X0 | Aarch64Register::W0 => {
                            // x0 is overwrittern basereg by op1 value.
                            //reload basereg to x1
                            writer.put_ldr_reg_reg_offset(
                                Aarch64Register::X1,
                                Aarch64Register::Sp,
                                0u64,
                            );
                        }
                        _ => {
                            writer.put_mov_reg_reg(Aarch64Register::W1, basereg);
                        }
                    }
                }

                // add displacement
                writer.put_add_reg_reg_imm(
                    Aarch64Register::X1,
                    Aarch64Register::X1,
                    displacement as u64,
                );
                //deref into x1 to get the real value
                writer.put_ldr_reg_reg_offset(Aarch64Register::X1, Aarch64Register::X1, 0u64);
            }
        }

        //call cmplog runtime to populate the values map
        writer.put_bytes(&self.ops_save_register_and_blr_to_populate());

        // Restore x0, x1
        assert!(writer.put_ldp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i64,
            IndexMode::PostAdjust,
        ));
    }

    #[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
    #[inline]
    /// Check if the current instruction is cmplog relevant one(any opcode which sets the flags)
    pub fn cmplog_is_interesting_instruction(
        &self,
        capstone: &Capstone,
        _address: u64,
        instr: &Insn,
    ) -> Result<
        (
            CmplogOperandType,
            CmplogOperandType,
            Option<SpecialCmpLogCase>,
        ),
        (),
    > {
        // We only care for compare instrunctions - aka instructions which set the flags
        match instr.mnemonic().unwrap() {
            "cmp" | "ands" | "subs" | "adds" | "negs" | "ngcs" | "sbcs" | "bics" | "cbz"
            | "cbnz" | "tbz" | "tbnz" | "adcs" => (),
            _ => return Err(()),
        }
        let mut operands = capstone
            .insn_detail(instr)
            .unwrap()
            .arch_detail()
            .operands();

        // cbz - 1 operand, tbz - 3 operands
        let special_case = [
            "cbz", "cbnz", "tbz", "tbnz", "subs", "adds", "ands", "sbcs", "bics", "adcs",
        ]
        .contains(&instr.mnemonic().unwrap());
        if operands.len() != 2 && !special_case {
            return Err(());
        }

        // handle special opcodes case which have 3 operands, but the 1st(dest) is not important to us
        if ["subs", "adds", "ands", "sbcs", "bics", "adcs"].contains(&instr.mnemonic().unwrap()) {
            //remove the dest operand from the list
            operands.remove(0);
        }

        // cbz marked as special since there is only 1 operand
        let special_case = match instr.mnemonic().unwrap() {
            "cbz" | "cbnz" => true,
            _ => false,
        };

        let operand1 = if let Arm64Operand(arm64operand) = operands.first().unwrap() {
            match arm64operand.op_type {
                Arm64OperandType::Reg(regid) => Some(CmplogOperandType::Regid(regid)),
                Arm64OperandType::Imm(val) => Some(CmplogOperandType::Imm(val as u64)),
                Arm64OperandType::Mem(opmem) => Some(CmplogOperandType::Mem(
                    opmem.base(),
                    opmem.index(),
                    opmem.disp(),
                    instruction_width(instr, &operands),
                )),
                Arm64OperandType::Cimm(val) => Some(CmplogOperandType::Cimm(val as u64)),
                _ => return Err(()),
            }
        } else {
            None
        };

        let operand2 = match special_case {
            true => Some(CmplogOperandType::Imm(0)),
            false => {
                if let Arm64Operand(arm64operand2) = &operands[1] {
                    match arm64operand2.op_type {
                        Arm64OperandType::Reg(regid) => Some(CmplogOperandType::Regid(regid)),
                        Arm64OperandType::Imm(val) => Some(CmplogOperandType::Imm(val as u64)),
                        Arm64OperandType::Mem(opmem) => Some(CmplogOperandType::Mem(
                            opmem.base(),
                            opmem.index(),
                            opmem.disp(),
                            instruction_width(instr, &operands),
                        )),
                        Arm64OperandType::Cimm(val) => Some(CmplogOperandType::Cimm(val as u64)),
                        _ => return Err(()),
                    }
                } else {
                    None
                }
            }
        };

        // tbz will need to have special handling at emit time(masking operand1 value with operand2)
        let special_case = match instr.mnemonic().unwrap() {
            "tbz" => Some(SpecialCmpLogCase::Tbz),
            "tbnz" => Some(SpecialCmpLogCase::Tbnz),
            _ => None,
        };

        if operand1.is_some() && operand2.is_some() {
            Ok((operand1.unwrap(), operand2.unwrap(), special_case))
        } else {
            Err(())
        }
    }
}

impl Default for CmpLogRuntime {
    fn default() -> Self {
        Self::new()
    }
}
