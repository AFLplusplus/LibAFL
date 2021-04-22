//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use libafl::{
    bolts::tuples::{tuple_list, Named},
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    events::{setup_restarting_mgr_std, EventManager},
    executors::{inprocess::InProcessExecutor, Executor, ExitKind, HasObservers},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{HasTargetBytes, Input},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    mutators::token_mutations::Tokens,
    observers::{HitcountsMapObserver, ObserversTuple, StdMapObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, State},
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
    Error,
};

use capstone::{
    arch::{self, arm64::Arm64OperandType, ArchOperand::Arm64Operand, BuildsCapstone},
    Capstone, Insn,
};
use core::cell::RefCell;
#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::X86Register;
#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::{Aarch64Register, IndexMode};
use frida_gum::{
    instruction_writer::InstructionWriter,
    stalker::{NoneEventSink, Stalker, StalkerOutput, Transformer},
};
use frida_gum::{Gum, MemoryRange, Module, NativePointer, PageProtection};
use num_traits::cast::FromPrimitive;

use rangemap::RangeMap;
use std::{env, ffi::c_void, fs::File, io::{BufWriter, Write}, path::PathBuf, rc::Rc};

use libafl_frida::{FridaOptions, asan_rt::{ASAN_ERRORS, AsanErrorsFeedback, AsanErrorsObserver, AsanRuntime}};

/// An helper that feeds FridaInProcessExecutor with user-supplied instrumentation
pub trait FridaHelper<'a, I: Input + HasTargetBytes> {
    fn transformer(&self) -> &Transformer<'a>;

    fn register_thread(&self);

    fn pre_exec(&self, input: &I);

    fn post_exec(&self, input: &I);
}

const MAP_SIZE: usize = 64 * 1024;

/// An helper that feeds FridaInProcessExecutor with edge-coverage instrumentation
struct FridaEdgeCoverageHelper<'a> {
    map: [u8; MAP_SIZE],
    previous_pc: [u64; 1],
    current_log_impl: u64,
    /// Transformer that has to be passed to FridaInProcessExecutor
    transformer: Option<Transformer<'a>>,
    capstone: Capstone,
    asan_runtime: Rc<RefCell<AsanRuntime>>,
    ranges: RangeMap<usize, (u16, &'a str)>,
    options: FridaOptions,
    drcov_basic_blocks: Vec<(usize, usize)>,
}

impl<'a, I: Input + HasTargetBytes> FridaHelper<'a, I> for FridaEdgeCoverageHelper<'a> {
    fn transformer(&self) -> &Transformer<'a> {
        self.transformer.as_ref().unwrap()
    }

    /// Register the current thread with the FridaEdgeCoverageHelper
    fn register_thread(&self) {
        self.asan_runtime.borrow().register_thread();
    }

    fn pre_exec(&self, input: &I) {
        let target_bytes = input.target_bytes();
        let slice = target_bytes.as_slice();
        //println!("target_bytes: {:02x?}", slice);
        self.asan_runtime
            .borrow()
            .unpoison(slice.as_ptr() as usize, slice.len());
    }

    fn post_exec(&self, input: &I) {
        if self.options.drcov_enabled() {
            let filename = format!(
                "./coverage/{:016x}.drcov",
                seahash::hash(input.target_bytes().as_slice())
            );
            DrCovWriter::new(&filename, &self.ranges, &self.drcov_basic_blocks).write();
        }

        if self.options.asan_enabled() {
            if self.options.asan_detect_leaks() {
                self.asan_runtime.borrow_mut().check_for_leaks();
            }
            self.asan_runtime.borrow_mut().reset_allocations();
        }
    }
}

struct DrCovWriter<'a> {
    writer: BufWriter<File>,
    module_mapping: &'a RangeMap<usize, (u16, &'a str)>,
    basic_blocks: &'a Vec<(usize, usize)>,
}

#[repr(C)]
struct DrCovBasicBlockEntry {
    start: u32,
    size: u16,
    mod_id: u16,
}

impl<'a> DrCovWriter<'a> {
    pub fn new(
        path: &str,
        module_mapping: &'a RangeMap<usize, (u16, &str)>,
        basic_blocks: &'a Vec<(usize, usize)>,
    ) -> Self {
        Self {
            writer: BufWriter::new(
                File::create(path).expect("unable to create file for coverage data"),
            ),
            module_mapping,
            basic_blocks,
        }
    }

    pub fn write(&mut self) {
        self.writer
            .write_all(b"DRCOV VERSION: 2\nDRCOV FLAVOR: libafl-frida\n")
            .unwrap();

        let modules: Vec<(&std::ops::Range<usize>, &(u16, &str))> =
            self.module_mapping.iter().collect();
        self.writer
            .write_all(format!("Module Table: version 2, count {}\n", modules.len()).as_bytes())
            .unwrap();
        self.writer
            .write_all(b"Columns: id, base, end, entry, checksum, timestamp, path\n")
            .unwrap();
        for module in modules {
            let (range, (id, path)) = module;
            self.writer
                .write_all(
                    format!(
                        "{:03}, 0x{:x}, 0x{:x}, 0x00000000, 0x00000000, 0x00000000, {}\n",
                        id, range.start, range.end, path
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
        self.writer
            .write_all(format!("BB Table: {} bbs\n", self.basic_blocks.len()).as_bytes())
            .unwrap();
        for (start, end) in self.basic_blocks {
            let (range, (id, _)) = self.module_mapping.get_key_value(&start).unwrap();
            let basic_block = DrCovBasicBlockEntry {
                start: (start - range.start) as u32,
                size: (end - start) as u16,
                mod_id: *id,
            };
            self.writer
                .write_all(unsafe {
                    std::slice::from_raw_parts(&basic_block as *const _ as *const u8, 8)
                })
                .unwrap();
        }

        self.writer.flush().unwrap();
    }
}

/// Helper function to get the size of a module's CODE section from frida
pub fn get_module_size(module_name: &str) -> usize {
    let mut code_size = 0;
    let code_size_ref = &mut code_size;
    Module::enumerate_ranges(module_name, PageProtection::ReadExecute, move |details| {
        *code_size_ref = details.memory_range().size() as usize;
        true
    });

    code_size
}

/// A minimal maybe_log implementation. We insert this into the transformed instruction stream
/// every time we need a copy that is within a direct branch of the start of the transformed basic
/// block.
#[cfg(target_arch = "x86_64")]
const MAYBE_LOG_CODE: [u8; 47] = [
    0x9c, /* pushfq */
    0x50, /* push rax */
    0x51, /* push rcx */
    0x52, /* push rdx */
    0x48, 0x8d, 0x05, 0x24, 0x00, 0x00, 0x00, /* lea rax, sym._afl_area_ptr_ptr */
    0x48, 0x8b, 0x00, /* mov rax, qword [rax] */
    0x48, 0x8d, 0x0d, 0x22, 0x00, 0x00, 0x00, /* lea rcx, sym.previous_pc     */
    0x48, 0x8b, 0x11, /* mov rdx, qword [rcx] */
    0x48, 0x8b, 0x12, /* mov rdx, qword [rdx] */
    0x48, 0x31, 0xfa, /* xor rdx, rdi */
    0xfe, 0x04, 0x10, /* inc byte [rax + rdx] */
    0x48, 0xd1, 0xef, /* shr rdi, 1 */
    0x48, 0x8b, 0x01, /* mov rax, qword [rcx] */
    0x48, 0x89, 0x38, /* mov qword [rax], rdi */
    0x5a, /* pop rdx */
    0x59, /* pop rcx */
    0x58, /* pop rax */
    0x9d, /* popfq */
    0xc3, /* ret */

          /* Read-only data goes here: */
          /* uint8_t* afl_area_ptr */
          /* uint64_t* afl_prev_loc_ptr */
];

#[cfg(target_arch = "aarch64")]
const MAYBE_LOG_CODE: [u8; 60] = [
    // __afl_area_ptr[current_pc ^ previous_pc]++;
    // previous_pc = current_pc >> 1;
    0xE1, 0x0B, 0xBF, 0xA9, // stp x1, x2, [sp, -0x10]!
    0xE3, 0x13, 0xBF, 0xA9, // stp x3, x4, [sp, -0x10]!
    // x0 = current_pc
    0xa1, 0x01, 0x00, 0x58, // ldr x1, #0x30, =__afl_area_ptr
    0x82, 0x01, 0x00, 0x58, // ldr x2, #0x38, =&previous_pc
    0x44, 0x00, 0x40, 0xf9, // ldr x4, [x2] (=previous_pc)
    // __afl_area_ptr[current_pc ^ previous_pc]++;
    0x84, 0x00, 0x00, 0xca, // eor x4, x4, x0
    0x84, 0x3c, 0x40, 0x92, // and x4, x4, 0xffff (=MAP_SIZE - 1)
    //0x20, 0x13, 0x20, 0xd4,
    0x23, 0x68, 0x64, 0xf8, // ldr x3, [x1, x4]
    0x63, 0x04, 0x00, 0x91, // add x3, x3, #1
    0x23, 0x68, 0x24, 0xf8, // str x3, [x1, x4]
    // previous_pc = current_pc >> 1;
    0xe0, 0x07, 0x40, 0x8b, // add x0, xzr, x0, LSR #1
    0x40, 0x00, 0x00, 0xf9, // str x0, [x2]
    0xE3, 0x13, 0xc1, 0xA8, // ldp x3, x4, [sp], #0x10
    0xE1, 0x0B, 0xc1, 0xA8, // ldp x1, x2, [sp], #0x10
    0xC0, 0x03, 0x5F, 0xD6, // ret

          // &afl_area_ptr
          // &afl_prev_loc_ptr
];

/// The implementation of the FridaEdgeCoverageHelper
impl<'a> FridaEdgeCoverageHelper<'a> {
    /// Constructor function to create a new FridaEdgeCoverageHelper, given a module_name.
    pub fn new(
        gum: &'a Gum,
        options: FridaOptions,
        _harness_module_name: &str,
        modules_to_instrument: &'a Vec<&str>,
    ) -> Self {
        let mut helper = Self {
            map: [0u8; MAP_SIZE],
            previous_pc: [0u64; 1],
            current_log_impl: 0,
            transformer: None,
            capstone: Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .expect("Failed to create Capstone object"),
            asan_runtime: AsanRuntime::new(options),
            ranges: RangeMap::new(),
            options,
            drcov_basic_blocks: vec![],
        };

        for (id, module_name) in modules_to_instrument.iter().enumerate() {
            let (lib_start, lib_end) = libafl_frida::asan_rt::mapping_for_library(module_name);
            println!("including range {:x}-{:x}", lib_start, lib_end);
            helper
                .ranges
                .insert(lib_start..lib_end, (id as u16, module_name));
        }

        if helper.options.drcov_enabled() {
            std::fs::create_dir("./coverage")
                .expect("failed to create directory for coverage files");
        }

        let transformer = Transformer::from_callback(gum, |basic_block, output| {
            let mut first = true;
            for instruction in basic_block {
                let instr = instruction.instr();
                let address = instr.address();
                //println!("address: {:x} contains: {:?}", address, helper.ranges.contains(&(address as usize)));
                if helper.ranges.contains_key(&(address as usize)) {
                    if first {
                        first = false;
                        //println!("block @ {:x} transformed to {:x}", address, output.writer().pc());
                        if helper.options.coverage_enabled() {
                            helper.emit_coverage_mapping(address, &output);
                        }
                        if helper.options.drcov_enabled() {
                            instruction.put_callout(|context| {
                                let real_address = match helper
                                    .asan_runtime
                                    .borrow()
                                    .real_address_for_stalked(context.pc() as usize)
                                {
                                    Some(address) => *address,
                                    _ => context.pc() as usize,
                                };
                                //let (range, (id, name)) = helper.ranges.get_key_value(&real_address).unwrap();
                                //println!("{}:0x{:016x}", name, real_address - range.start);
                                helper
                                    .drcov_basic_blocks
                                    .push((real_address, real_address + 4));
                            })
                        }
                    }

                    if helper.options.asan_enabled() {
                        if let Ok((basereg, indexreg, displacement, width)) =
                            helper.is_interesting_instruction(address, instr)
                        {
                            helper.emit_shadow_check(
                                address,
                                &output,
                                basereg,
                                indexreg,
                                displacement,
                                width,
                            );
                        }
                    }
                    if helper.options.asan_enabled() || helper.options.drcov_enabled() {
                        helper
                            .asan_runtime
                            .borrow_mut()
                            .add_stalked_address(output.writer().pc() as usize - 4, address as usize);
                    }
                }
                instruction.keep()
            }
        });
        helper.transformer = Some(transformer);
        if helper.options.asan_enabled() || helper.options.asan_enabled() {
            helper.asan_runtime.borrow_mut().init(modules_to_instrument);
        }
        helper
    }

    #[inline]
    fn get_writer_register(&self, reg: capstone::RegId) -> Aarch64Register {
        let regint: u16 = reg.0;
        Aarch64Register::from_u32(regint as u32).unwrap()
    }

    #[inline]
    fn emit_shadow_check(
        &self,
        _address: u64,
        output: &StalkerOutput,
        basereg: capstone::RegId,
        indexreg: capstone::RegId,
        displacement: i32,
        width: u32,
    ) {
        let writer = output.writer();

        let basereg = self.get_writer_register(basereg);
        let indexreg = if indexreg.0 != 0 {
            Some(self.get_writer_register(indexreg))
        } else {
            None
        };

        //writer.put_brk_imm(1);

        // Preserve x0, x1:
        writer.put_stp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            -(16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i32) as i64,
            IndexMode::PreAdjust,
        );

        // Make sure the base register is copied into x0
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

        // Make sure the index register is copied into x1
        if indexreg.is_some() {
            if let Some(indexreg) = indexreg {
                match indexreg {
                    Aarch64Register::X0 | Aarch64Register::W0 => {
                        writer.put_ldr_reg_reg_offset(
                            Aarch64Register::X1,
                            Aarch64Register::Sp,
                            0u64,
                        );
                    }
                    Aarch64Register::X1 | Aarch64Register::W1 => {}
                    _ => {
                        if !writer.put_mov_reg_reg(Aarch64Register::X1, indexreg) {
                            writer.put_mov_reg_reg(Aarch64Register::W1, indexreg);
                        }
                    }
                }
            }
            writer.put_add_reg_reg_reg(
                Aarch64Register::X0,
                Aarch64Register::X0,
                Aarch64Register::X1,
            );
        }

        let displacement = displacement
            + if basereg == Aarch64Register::Sp {
                16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i32
            } else {
                0
            };

        #[allow(clippy::comparison_chain)]
        if displacement < 0 {
            if displacement > -4096 {
                // Subtract the displacement into x0
                writer.put_sub_reg_reg_imm(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    displacement.abs() as u64,
                );
            } else {
                let displacement_hi = displacement.abs() / 4096;
                let displacement_lo = displacement.abs() % 4096;
                writer.put_bytes(&(0xd1400000u32 | ((displacement_hi as u32) << 10)).to_le_bytes());
                writer.put_sub_reg_reg_imm(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    displacement_lo as u64,
                );
            }
        } else if displacement > 0 {
            if displacement < 4096 {
                // Add the displacement into x0
                writer.put_add_reg_reg_imm(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    displacement as u64,
                );
            } else {
                let displacement_hi = displacement / 4096;
                let displacement_lo = displacement % 4096;
                writer.put_bytes(&(0x91400000u32 | ((displacement_hi as u32) << 10)).to_le_bytes());
                writer.put_add_reg_reg_imm(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    displacement_lo as u64,
                );
            }
        }
        // Insert the check_shadow_mem code blob
        match width {
            1 => writer.put_bytes(&self.asan_runtime.borrow().blob_check_mem_byte()),
            2 => writer.put_bytes(&self.asan_runtime.borrow().blob_check_mem_halfword()),
            3 => writer.put_bytes(&self.asan_runtime.borrow().blob_check_mem_3bytes()),
            4 => writer.put_bytes(&self.asan_runtime.borrow().blob_check_mem_dword()),
            6 => writer.put_bytes(&self.asan_runtime.borrow().blob_check_mem_6bytes()),
            8 => writer.put_bytes(&self.asan_runtime.borrow().blob_check_mem_qword()),
            12 => writer.put_bytes(&self.asan_runtime.borrow().blob_check_mem_12bytes()),
            16 => writer.put_bytes(&self.asan_runtime.borrow().blob_check_mem_16bytes()),
            24 => writer.put_bytes(&self.asan_runtime.borrow().blob_check_mem_24bytes()),
            32 => writer.put_bytes(&self.asan_runtime.borrow().blob_check_mem_32bytes()),
            _ => false,
        };

        // Restore x0, x1
        assert!(writer.put_ldp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i64,
            IndexMode::PostAdjust,
        ));
    }

    #[inline]
    fn get_instruction_width(&self, instr: &Insn, operands: &Vec<arch::ArchOperand>) -> u32 {
        use capstone::arch::arm64::Arm64Insn as I;
        use capstone::arch::arm64::Arm64Reg as R;
        use capstone::arch::arm64::Arm64Vas as V;

        let num_registers = match instr.id().0.into() {
            I::ARM64_INS_STP
            | I::ARM64_INS_STXP
            | I::ARM64_INS_STNP
            | I::ARM64_INS_STLXP
            | I::ARM64_INS_LDP
            | I::ARM64_INS_LDXP
            | I::ARM64_INS_LDNP => 2,
            _ => 1,
        };

        let mnemonic = instr.mnemonic().unwrap();
        match mnemonic.as_bytes().last().unwrap() {
            b'b' => return 1,
            b'h' => return 2,
            b'w' => return 4 * num_registers,
            _ => (),
        }

        if let Arm64Operand(operand) = operands.first().unwrap() {
            if operand.vas != V::ARM64_VAS_INVALID {
                let count_byte: u32 = if mnemonic.starts_with("st") || mnemonic.starts_with("ld") {
                    mnemonic.chars().nth(2).unwrap().to_digit(10).unwrap()
                } else {
                    1
                };

                return match operand.vas {
                    V::ARM64_VAS_1B => 1 * count_byte,
                    V::ARM64_VAS_1H => 2 * count_byte,
                    V::ARM64_VAS_4B | V::ARM64_VAS_1S | V::ARM64_VAS_1D | V::ARM64_VAS_2H => {
                        4 * count_byte
                    }
                    V::ARM64_VAS_8B
                    | V::ARM64_VAS_4H
                    | V::ARM64_VAS_2S
                    | V::ARM64_VAS_2D
                    | V::ARM64_VAS_1Q => 8 * count_byte,
                    V::ARM64_VAS_8H | V::ARM64_VAS_4S | V::ARM64_VAS_16B => 16 * count_byte,
                    V::ARM64_VAS_INVALID => {
                        panic!("should not be reached");
                    }
                };
            } else if let Arm64OperandType::Reg(operand) = operand.op_type {
                match operand.0 as u32 {
                    R::ARM64_REG_W0..=R::ARM64_REG_W30
                    | R::ARM64_REG_WZR
                    | R::ARM64_REG_WSP
                    | R::ARM64_REG_S0..=R::ARM64_REG_S31 => return 4 * num_registers,
                    R::ARM64_REG_D0..=R::ARM64_REG_D31 => return 8 * num_registers,
                    R::ARM64_REG_Q0..=R::ARM64_REG_Q31 => return 16,
                    _ => (),
                }
            };
        };

        8 * num_registers
    }

    #[inline]
    fn is_interesting_instruction(
        &self,
        _address: u64,
        instr: &Insn,
    ) -> Result<(capstone::RegId, capstone::RegId, i32, u32), ()> {
        // We have to ignore these instructions. Simulating them with their side effects is
        // complex, to say the least.
        match instr.mnemonic().unwrap() {
            "ldaxr" | "stlxr" | "ldxr" | "stxr" | "ldar" | "stlr" | "ldarb" | "ldarh" | "ldaxp"
            | "ldaxrb" | "ldaxrh" | "stlrb" | "stlrh" | "stlxp" | "stlxrb" | "stlxrh" | "ldxrb"
            | "ldxrh" | "stxrb" | "stxrh" => return Err(()),
            _ => (),
        }

        let operands = self
            .capstone
            .insn_detail(instr)
            .unwrap()
            .arch_detail()
            .operands();
        if operands.len() < 2 {
            return Err(());
        }

        if let Arm64Operand(arm64operand) = operands.last().unwrap() {
            if let Arm64OperandType::Mem(opmem) = arm64operand.op_type {
                return Ok((
                    opmem.base(),
                    opmem.index(),
                    opmem.disp(),
                    self.get_instruction_width(instr, &operands),
                ));
            }
        }

        Err(())
    }

    #[inline]
    fn emit_coverage_mapping(&mut self, address: u64, output: &StalkerOutput) {
        let writer = output.writer();
        if self.current_log_impl == 0
            || !writer.can_branch_directly_to(self.current_log_impl)
            || !writer.can_branch_directly_between(writer.pc() + 128, self.current_log_impl)
        {
            let after_log_impl = writer.code_offset() + 1;

            #[cfg(target_arch = "x86_64")]
            writer.put_jmp_near_label(after_log_impl);
            #[cfg(target_arch = "aarch64")]
            writer.put_b_label(after_log_impl);

            self.current_log_impl = writer.pc();
            writer.put_bytes(&MAYBE_LOG_CODE);
            let prev_loc_pointer = self.previous_pc.as_ptr() as usize;
            let map_pointer = self.map.as_ptr() as usize;

            writer.put_bytes(&map_pointer.to_ne_bytes());
            writer.put_bytes(&prev_loc_pointer.to_ne_bytes());

            writer.put_label(after_log_impl);
        }
        #[cfg(target_arch = "x86_64")]
        {
            println!("here");
            writer.put_lea_reg_reg_offset(
                X86Register::Rsp,
                X86Register::Rsp,
                -(frida_gum_sys::GUM_RED_ZONE_SIZE as i32),
            );
            writer.put_push_reg(X86Register::Rdi);
            writer.put_mov_reg_address(
                X86Register::Rdi,
                ((address >> 4) ^ (address << 8)) & (MAP_SIZE - 1) as u64,
            );
            writer.put_call_address(self.current_log_impl);
            writer.put_pop_reg(X86Register::Rdi);
            writer.put_lea_reg_reg_offset(
                X86Register::Rsp,
                X86Register::Rsp,
                frida_gum_sys::GUM_RED_ZONE_SIZE as i32,
            );
        }
        #[cfg(target_arch = "aarch64")]
        {
            writer.put_stp_reg_reg_reg_offset(
                Aarch64Register::Lr,
                Aarch64Register::X0,
                Aarch64Register::Sp,
                -(16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i32) as i64,
                IndexMode::PreAdjust,
            );
            writer.put_ldr_reg_u64(
                Aarch64Register::X0,
                ((address >> 4) ^ (address << 8)) & (MAP_SIZE - 1) as u64,
            );
            writer.put_bl_imm(self.current_log_impl);
            writer.put_ldp_reg_reg_reg_offset(
                Aarch64Register::Lr,
                Aarch64Register::X0,
                Aarch64Register::Sp,
                16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i64,
                IndexMode::PostAdjust,
            );
        }
    }
}

struct FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a, I>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    base: InProcessExecutor<'a, H, I, OT>,
    /// Frida's dynamic rewriting engine
    stalker: Stalker<'a>,
    /// User provided callback for instrumentation
    helper: &'a FH,
    followed: bool,
}

impl<'a, FH, H, I, OT> Executor<I> for FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a, I>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// Called right before exexution starts
    #[inline]
    fn pre_exec<EM, S>(&mut self, state: &mut S, event_mgr: &mut EM, input: &I) -> Result<(), Error>
    where
        EM: EventManager<I, S>,
    {
        if !self.followed {
            self.followed = true;
            self.stalker
                .follow_me::<NoneEventSink>(self.helper.transformer(), None);
        } else {
            self.stalker.activate(NativePointer(
                self.base.harness_mut() as *mut _ as *mut c_void
            ))
        }

        self.helper.pre_exec(input);

        self.base.pre_exec(state, event_mgr, input)
    }

    /// Instruct the target about the input and run
    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        self.base.run_target(input)
    }

    /// Called right after execution finished.
    #[inline]
    fn post_exec<EM, S>(
        &mut self,
        state: &mut S,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error>
    where
        EM: EventManager<I, S>,
    {
        self.stalker.deactivate();
        self.helper.post_exec(input);
        self.base.post_exec(state, event_mgr, input)
    }
}

impl<'a, FH, H, I, OT> HasObservers<OT> for FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a, I>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.base.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.base.observers_mut()
    }
}

impl<'a, FH, H, I, OT> Named for FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a, I>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    fn name(&self) -> &str {
        self.base.name()
    }
}

impl<'a, FH, H, I, OT> FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a, I>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(gum: &'a Gum, base: InProcessExecutor<'a, H, I, OT>, helper: &'a FH) -> Self {
        let mut stalker = Stalker::new(gum);

        // Let's exclude the main module and libc.so at least:
        stalker.exclude(&MemoryRange::new(
            Module::find_base_address(&env::args().next().unwrap()),
            get_module_size(&env::args().next().unwrap()),
        ));
        //stalker.exclude(&MemoryRange::new(
        //Module::find_base_address("libc.so"),
        //get_module_size("libc.so"),
        //));

        Self {
            base,
            stalker,
            helper,
            followed: false,
        }
    }
}

/// The main fn, usually parsing parameters, and starting the fuzzer
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    unsafe {
        fuzz(
            &env::args().nth(1).expect("no module specified"),
            &env::args().nth(2).expect("no symbol specified"),
            env::args()
                .nth(3)
                .expect("no modules to instrument specified")
                .split(":")
                .collect(),
            vec![PathBuf::from("./corpus")],
            PathBuf::from("./crashes"),
            1337,
        )
        .expect("An error occurred while fuzzing");
    }
}

/// Not supported on windows right now
#[cfg(windows)]
fn fuzz(
    _module_name: &str,
    _symbol_name: &str,
    _corpus_dirs: Vec<PathBuf>,
    _objective_dir: PathBuf,
    _broker_port: u16,
) -> Result<(), ()> {
    todo!("Example not supported on Windows");
}

/// The actual fuzzer
#[cfg(unix)]
unsafe fn fuzz(
    module_name: &str,
    symbol_name: &str,
    modules_to_instrument: Vec<&str>,
    corpus_dirs: Vec<PathBuf>,
    objective_dir: PathBuf,
    broker_port: u16,
) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) = match setup_restarting_mgr_std(stats, broker_port) {
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {}", err);
            }
        },
    };

    let gum = Gum::obtain();

    let lib = libloading::Library::new(module_name).unwrap();
    let target_func: libloading::Symbol<unsafe extern "C" fn(data: *const u8, size: usize) -> i32> =
        lib.get(symbol_name.as_bytes()).unwrap();

    let mut frida_helper = FridaEdgeCoverageHelper::new(&gum, FridaOptions::parse_env_options(), module_name, &modules_to_instrument);

    // Create an observation channel using the coverage map
    let edges_observer = HitcountsMapObserver::new(StdMapObserver::new_from_ptr(
        "edges",
        frida_helper.map.as_mut_ptr(),
        MAP_SIZE,
    ));

    let mut frida_harness = move |buf: &[u8]| {
        (target_func)(buf.as_ptr(), buf.len());
        ExitKind::Ok
    };

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        State::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Feedbacks to rate the interestingness of an input
            tuple_list!(MaxMapFeedback::new_with_observer_track(
                &edges_observer,
                true,
                false
            )),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // Feedbacks to recognize an input as solution
            tuple_list!(CrashFeedback::new(), AsanErrorsFeedback::new()),
        )
    });

    println!("We're a client, let's fuzz :)");

    // Create a PNG dictionary if not existing
    if state.metadata().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::new(vec![
            vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header
            b"IHDR".to_vec(),
            b"IDAT".to_vec(),
            b"PLTE".to_vec(),
            b"IEND".to_vec(),
        ]));
    }

    // Setup a basic mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let stage = StdMutationalStage::new(mutator);

    // A fuzzer with just one stage and a minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = FridaInProcessExecutor::new(
        &gum,
        InProcessExecutor::new(
            "in-process(edges)",
            &mut frida_harness,
            tuple_list!(edges_observer, AsanErrorsObserver::new(&ASAN_ERRORS)),
            &mut state,
            &mut restarting_mgr,
        )?,
        &frida_helper,
    );
    // Let's exclude the main module and libc.so at least:
    executor.stalker.exclude(&MemoryRange::new(
        Module::find_base_address(&env::args().next().unwrap()),
        get_module_size(&env::args().next().unwrap()),
    ));
    //executor.stalker.exclude(&MemoryRange::new(
    //Module::find_base_address("libc.so"),
    //get_module_size("libc.so"),
    //));

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut executor, &mut restarting_mgr, &scheduler, &corpus_dirs)
            .expect(&format!(
                "Failed to load initial corpus at {:?}",
                &corpus_dirs
            ));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut state, &mut executor, &mut restarting_mgr, &scheduler)?;

    // Never reached
    Ok(())
}
