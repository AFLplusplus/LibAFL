use ahash::AHasher;
use std::hash::Hasher;

use libafl::inputs::{HasTargetBytes, Input};

use libafl_targets::drcov::{DrCovBasicBlock, DrCovWriter};

#[cfg(target_arch = "aarch64")]
use capstone::{
    arch::{
        self,
        arm64::{Arm64Extender, Arm64OperandType, Arm64Shift},
        ArchOperand::Arm64Operand,
        BuildsCapstone,
    },
    Capstone, Insn,
};

#[cfg(target_arch = "x86_64")]
use capstone::{
    arch::{self, x86::{X86OperandType, X86InsnDetail, X86Insn}, ArchOperand::X86Operand, BuildsCapstone},
    Capstone, Insn, RegId,
};

#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::X86Register;
#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::{Aarch64Register, IndexMode};
use frida_gum::{
    instruction_writer::InstructionWriter,
    stalker::{StalkerOutput, Transformer},
    CpuContext, ModuleDetails, ModuleMap,
};
use frida_gum::{Gum, Module, PageProtection};

use rangemap::RangeMap;

#[cfg(unix)]
use nix::sys::mman::{mmap, MapFlags, ProtFlags};

#[cfg(unix)]
use crate::{asan_rt::AsanRuntime, FridaOptions};

#[cfg(windows)]
use crate::FridaOptions;

#[cfg(feature = "cmplog")]
use crate::cmplog_rt::CmpLogRuntime;

#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
enum CmplogOperandType {
    Regid(capstone::RegId),
    Imm(u64),
    Cimm(u64),
    Mem(capstone::RegId, capstone::RegId, i32, u32),
}

#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
enum SpecialCmpLogCase {
    Tbz,
    Tbnz,
}

#[cfg(target_vendor = "apple")]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANON;
#[cfg(not(any(target_vendor = "apple", target_os = "windows")))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANONYMOUS;

/// An helper that feeds [`FridaInProcessExecutor`] with user-supplied instrumentation
pub trait FridaHelper<'a> {
    /// Access to the stalker `Transformer`
    fn transformer(&self) -> &Transformer<'a>;

    /// Register a new thread with this `FridaHelper`
    #[cfg(unix)]
    fn register_thread(&mut self);

    /// Called prior to execution of an input
    fn pre_exec<I: Input + HasTargetBytes>(&mut self, input: &I);

    /// Called after execution of an input
    fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I);

    /// Returns `true` if stalker is enabled
    fn stalker_enabled(&self) -> bool;

    /// pointer to the frida coverage map
    fn map_ptr(&mut self) -> *mut u8;

    fn ranges(&self) -> &RangeMap<usize, (u16, String)>;
}

/// (Default) map size for frida coverage reporting
pub const MAP_SIZE: usize = 64 * 1024;

/// An helper that feeds [`FridaInProcessExecutor`] with edge-coverage instrumentation
pub struct FridaInstrumentationHelper<'a> {
    map: [u8; MAP_SIZE],
    previous_pc: [u64; 1],
    current_log_impl: u64,
    current_report_impl: u64,
    /// Transformer that has to be passed to FridaInProcessExecutor
    transformer: Option<Transformer<'a>>,
    capstone: Capstone,
    #[cfg(unix)]
    asan_runtime: AsanRuntime,
    #[cfg(feature = "cmplog")]
    cmplog_runtime: CmpLogRuntime,
    ranges: RangeMap<usize, (u16, String)>,
    module_map: ModuleMap,
    options: &'a FridaOptions,
    drcov_basic_blocks: Vec<DrCovBasicBlock>,
}

impl<'a> FridaHelper<'a> for FridaInstrumentationHelper<'a> {
    fn transformer(&self) -> &Transformer<'a> {
        self.transformer.as_ref().unwrap()
    }

    /// Register the current thread with the [`FridaInstrumentationHelper`]
    #[cfg(unix)]
    fn register_thread(&mut self) {
        self.asan_runtime.register_thread();
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn pre_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) {}

    #[cfg(target_arch = "aarch64")]
    fn pre_exec<I: Input + HasTargetBytes>(&mut self, input: &I) {
        #[cfg(target_arch = "aarch64")]
        let target_bytes = input.target_bytes();
        let slice = target_bytes.as_slice();
        //println!("target_bytes: {:#x}: {:02x?}", slice.as_ptr() as usize, slice);
        #[cfg(target_arch = "aarch64")]
        if self.options.asan_enabled() {
            self.asan_runtime
                .unpoison(slice.as_ptr() as usize, slice.len());
        }
    }

    fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) {
        if self.options.drcov_enabled() {
            let mut hasher = AHasher::new_with_keys(0, 0);
            hasher.write(input.target_bytes().as_slice());

            let filename = format!("./coverage/{:016x}.drcov", hasher.finish(),);
            DrCovWriter::new(&filename, &self.ranges, &mut self.drcov_basic_blocks).write();
        }

        #[cfg(target_arch = "aarch64")]
        if self.options.asan_enabled() {
            if self.options.asan_detect_leaks() {
                self.asan_runtime.check_for_leaks();
            }

            let target_bytes = input.target_bytes();
            let slice = target_bytes.as_slice();
            self.asan_runtime
                .poison(slice.as_ptr() as usize, slice.len());
            self.asan_runtime.reset_allocations();
        }
    }

    fn stalker_enabled(&self) -> bool {
        self.options.stalker_enabled()
    }

    fn map_ptr(&mut self) -> *mut u8 {
        self.map.as_mut_ptr()
    }

    fn ranges(&self) -> &RangeMap<usize, (u16, String)> {
        &self.ranges
    }
}

/// Helper function to get the size of a module's CODE section from frida
#[must_use]
pub fn get_module_size(module_name: &str) -> usize {
    let mut code_size = 0;
    let code_size_ref = &mut code_size;
    Module::enumerate_ranges(module_name, PageProtection::ReadExecute, move |details| {
        *code_size_ref = details.memory_range().size() as usize;
        true
    });

    code_size
}

/// A minimal `maybe_log` implementation. We insert this into the transformed instruction stream
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

#[cfg(target_arch = "aarch64")]
fn pc(context: &CpuContext) -> usize {
    context.pc() as usize
}

#[cfg(target_arch = "x86_64")]
fn pc(context: &CpuContext) -> usize {
    context.rip() as usize
}

/// The implementation of the [`FridaInstrumentationHelper`]
impl<'a> FridaInstrumentationHelper<'a> {
    /// Constructor function to create a new [`FridaInstrumentationHelper`], given a `module_name`.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn new(
        gum: &'a Gum,
        options: &'a FridaOptions,
        _harness_module_name: &str,
        modules_to_instrument: &'a [&str],
    ) -> Self {
        // workaround frida's frida-gum-allocate-near bug:
        #[cfg(unix)]
        unsafe {
            for _ in 0..512 {
                mmap(
                    std::ptr::null_mut(),
                    128 * 1024,
                    ProtFlags::PROT_NONE,
                    ANONYMOUS_FLAG | MapFlags::MAP_PRIVATE | MapFlags::MAP_NORESERVE,
                    -1,
                    0,
                )
                .expect("Failed to map dummy regions for frida workaround");
                mmap(
                    std::ptr::null_mut(),
                    4 * 1024 * 1024,
                    ProtFlags::PROT_NONE,
                    ANONYMOUS_FLAG | MapFlags::MAP_PRIVATE | MapFlags::MAP_NORESERVE,
                    -1,
                    0,
                )
                .expect("Failed to map dummy regions for frida workaround");
            }
        }

        let mut helper = Self {
            map: [0u8; MAP_SIZE],
            previous_pc: [0u64; 1],
            current_log_impl: 0,
            current_report_impl: 0,
            transformer: None,
            #[cfg(target_arch = "aarch64")]
            capstone: Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .expect("Failed to create Capstone object"),
            #[cfg(target_arch = "x86_64")]
            capstone: Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .detail(true)
                .build()
                .expect("Failed to create Capstone object"),
            #[cfg(not(windows))]
            asan_runtime: AsanRuntime::new(options.clone()),
            #[cfg(feature = "cmplog")]
            cmplog_runtime: CmpLogRuntime::new(),
            ranges: RangeMap::new(),
            module_map: ModuleMap::new_from_names(modules_to_instrument),
            options,
            drcov_basic_blocks: vec![],
        };

        if helper.options().stalker_enabled() {
            for (i, module) in helper.module_map.values().iter().enumerate() {
                let range = module.range();
                let start = range.base_address().0 as usize;
                helper
                    .ranges
                    .insert(start..(start + range.size()), (i as u16, module.path()));
            }
            if let Some(suppressed_specifiers) = helper.options().dont_instrument_locations() {
                for (module_name, offset) in suppressed_specifiers {
                    let module_details = ModuleDetails::with_name(module_name).unwrap();
                    let lib_start = module_details.range().base_address().0 as usize;
                    println!("removing address: {:#x}", lib_start + offset);
                    helper
                        .ranges
                        .remove((lib_start + offset)..(lib_start + offset + 4));
                }
            }

            if helper.options().drcov_enabled() {
                std::fs::create_dir_all("./coverage")
                    .expect("failed to create directory for coverage files");
            }

            let transformer = Transformer::from_callback(gum, |basic_block, output| {
                let mut first = true;
                for instruction in basic_block {
                    let instr = instruction.instr();
                    let address = instr.address();
                    //println!("block @ {:x} transformed to {:x}", address, output.writer().pc());
                    //println!("address: {:x} contains: {:?}", address, helper.ranges.contains_key(&(address as usize)));
                    if helper.ranges.contains_key(&(address as usize)) {
                        if first {
                            first = false;
                            //println!("block @ {:x} transformed to {:x}", address, output.writer().pc());
                            if helper.options().coverage_enabled() {
                                helper.emit_coverage_mapping(address, &output);
                            }
                            #[cfg(unix)]
                            if helper.options().drcov_enabled() {
                                instruction.put_callout(|context| {
                                    let real_address =
                                        helper.asan_runtime.real_address_for_stalked(pc(&context));
                                    //let (range, (id, name)) = helper.ranges.get_key_value(&real_address).unwrap();
                                    //println!("{}:0x{:016x}", name, real_address - range.start);
                                    helper
                                        .drcov_basic_blocks
                                        .push(DrCovBasicBlock::new(real_address, real_address + 4));
                                });
                            }
                        }

                        if helper.options().asan_enabled() {
                            #[cfg(target_arch = "x86_64")]
                            if let Ok((segment, width, basereg, indexreg, scale, disp)) =
                                helper.asan_is_interesting_instruction(address, instr)
                            {
                                helper.emit_shadow_check(
                                    address, &output, segment, width, basereg, indexreg, scale, disp,
                                );
                            }
                            #[cfg(target_arch = "aarch64")]
                            if let Ok((basereg, indexreg, displacement, width, shift, extender)) =
                                helper.asan_is_interesting_instruction(address, instr)
                            {
                                helper.emit_shadow_check(
                                    address,
                                    &output,
                                    basereg,
                                    indexreg,
                                    displacement,
                                    width,
                                    shift,
                                    extender,
                                );
                            }
                        }
                        if helper.options().cmplog_enabled() {
                            #[cfg(not(target_arch = "aarch64"))]
                            todo!("Implement cmplog for non-aarch64 targets");
                            #[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
                            // check if this instruction is a compare instruction and if so save the registers values
                            if let Ok((op1, op2, special_case)) =
                                helper.cmplog_is_interesting_instruction(address, instr)
                            {
                                //emit code that saves the relevant data in runtime(passes it to x0, x1)
                                helper.emit_comparison_handling(
                                    address,
                                    &output,
                                    op1,
                                    op2,
                                    special_case,
                                );
                            }
                        }

                        #[cfg(unix)]
                        if helper.options().asan_enabled() || helper.options().drcov_enabled() {
                            helper.asan_runtime.add_stalked_address(
                                output.writer().pc() as usize - 4,
                                address as usize,
                            );
                        }
                    }
                    instruction.keep();
                }
            });
            helper.transformer = Some(transformer);

            #[cfg(unix)]
            if helper.options().asan_enabled() || helper.options().drcov_enabled() {
                helper.asan_runtime.init(gum, modules_to_instrument);
            }
            #[cfg(feature = "cmplog")]
            if helper.options.cmplog_enabled() {
                helper.cmplog_runtime.init();
            }
        }
        helper
    }

    #[inline]
    fn options(&self) -> &FridaOptions {
        self.options
    }
    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn writer_register(&self, reg: capstone::RegId) -> Aarch64Register {
        let regint: u16 = reg.0;
        Aarch64Register::from_u32(regint as u32).unwrap()
    }


    // frida registers: https://docs.rs/frida-gum/0.4.0/frida_gum/instruction_writer/enum.X86Register.html
    // capstone registers: https://docs.rs/capstone-sys/0.14.0/capstone_sys/x86_reg/index.html
    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn writer_register(&self, reg: RegId) -> X86Register {
        let regint: u16 = reg.0;
        match regint {
            19 => X86Register::Eax,
            22 => X86Register::Ecx,
            24 => X86Register::Edx,
            21 => X86Register::Ebx,
            30 => X86Register::Esp,
            20 => X86Register::Ebp,
            29 => X86Register::Esi,
            23 => X86Register::Edi,
            226 => X86Register::R8d,
            227 => X86Register::R9d,
            228 => X86Register::R10d,
            229 => X86Register::R11d,
            230 => X86Register::R12d,
            231 => X86Register::R13d,
            232 => X86Register::R14d,
            233 => X86Register::R15d,
            26 => X86Register::Eip,
            35 => X86Register::Rax,
            38 => X86Register::Rcx,
            40 => X86Register::Rdx,
            37 => X86Register::Rbx,
            44 => X86Register::Rsp,
            36 => X86Register::Rbp,
            43 => X86Register::Rsi,
            39 => X86Register::Rdi,
            106 => X86Register::R8,
            107 => X86Register::R9,
            108 => X86Register::R10,
            109 => X86Register::R11,
            110 => X86Register::R12,
            111 => X86Register::R13,
            112 => X86Register::R14,
            113 => X86Register::R15,
            41 => X86Register::Rip,
            _ => X86Register::None, // Ignore Xax..Xip
        }
    }


    #[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
    #[inline]
    /// Emit the instrumentation code which is responsible for opernads value extraction and cmplog map population
    fn emit_comparison_handling(
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
                let reg = self.writer_register(reg);
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
                let basereg = self.writer_register(basereg);
                let indexreg = if indexreg.0 != 0 {
                    Some(self.writer_register(indexreg))
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
                            writer.put_bytes(&self.cmplog_runtime.ops_handle_tbz_masking());
                        }
                        SpecialCmpLogCase::Tbnz => {
                            writer.put_bytes(&self.cmplog_runtime.ops_handle_tbnz_masking());
                        }
                    },
                    None => (),
                }
            }
            CmplogOperandType::Regid(reg) => {
                let reg = self.writer_register(reg);
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
                let basereg = self.writer_register(basereg);
                let indexreg = if indexreg.0 != 0 {
                    Some(self.writer_register(indexreg))
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
        writer.put_bytes(&self.cmplog_runtime.ops_save_register_and_blr_to_populate());

        // Restore x0, x1
        assert!(writer.put_ldp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            16 + frida_gum_sys::GUM_RED_ZONE_SIZE as i64,
            IndexMode::PostAdjust,
        ));
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn emit_shadow_check(
        &mut self,
        _address: u64,
        output: &StalkerOutput,
        _segment: RegId,
        width: u8,
        basereg: RegId,
        indexreg: RegId,
        scale: i32,
        disp: i64,
    ) {
        let redzone_size = frida_gum_sys::GUM_RED_ZONE_SIZE as i64;

        let writer = output.writer();

        let basereg = if basereg.0 != 0 {
            Some(self.writer_register(basereg))
        } else {
            None
        };

        let indexreg = if indexreg.0 != 0 {
            Some(self.writer_register(indexreg))
        } else {
            None
        };

        let scale = match scale {
            2 => 1,
            4 => 2,
            8 => 3,
            _ => 0,
        };


        if self.current_report_impl == 0
            || !writer.can_branch_directly_to(self.current_report_impl)
            || !writer.can_branch_directly_between(writer.pc() + 128, self.current_report_impl)
        {
            let after_report_impl = writer.code_offset() + 2;

            #[cfg(target_arch = "x86_64")]
            writer.put_jmp_near_label(after_report_impl);
            #[cfg(target_arch = "aarch64")]
            writer.put_b_label(after_report_impl);

            self.current_report_impl = writer.pc();

            #[cfg(unix)]
            writer.put_bytes(self.asan_runtime.blob_report());

            writer.put_label(after_report_impl);
        }
        writer.put_lea_reg_reg_offset(X86Register::Rsp, X86Register::Rsp, -redzone_size);
        writer.put_push_reg(X86Register::Rdi);
        writer.put_push_reg(X86Register::Rsi);

        // Init Rdi
        if basereg.is_some(){
            writer.put_mov_reg_reg(X86Register::Rdi, basereg.unwrap());
        }
        else {
            writer.put_xor_reg_reg(X86Register::Rdi, X86Register::Rdi);
        }

        // Init Rsi
        if indexreg.is_some(){
            writer.put_mov_reg_reg(X86Register::Rsi, indexreg.unwrap());
        }
        else {
            writer.put_xor_reg_reg(X86Register::Rsi, X86Register::Rsi);
        }

        // Scale
        if scale > 0 {
            writer.put_shl_reg_u8(X86Register::Rsi, scale);
        }

        // Finally set Rdi to base + index * scale + disp
        writer.put_add_reg_reg(X86Register::Rdi, X86Register::Rsi);
        writer.put_lea_reg_reg_offset(X86Register::Rdi, X86Register::Rdi, disp);

        /*
        #[cfg(unix)]
        match width {
            1 => writer.put_bytes(&self.asan_runtime.blob_check_mem_byte()),
            2 => writer.put_bytes(&self.asan_runtime.blob_check_mem_halfword()),
            3 => writer.put_bytes(&self.asan_runtime.blob_check_mem_3bytes()),
            4 => writer.put_bytes(&self.asan_runtime.blob_check_mem_dword()),
            6 => writer.put_bytes(&self.asan_runtime.blob_check_mem_6bytes()),
            8 => writer.put_bytes(&self.asan_runtime.blob_check_mem_qword()),
            12 => writer.put_bytes(&self.asan_runtime.blob_check_mem_12bytes()),
            16 => writer.put_bytes(&self.asan_runtime.blob_check_mem_16bytes()),
            24 => writer.put_bytes(&self.asan_runtime.blob_check_mem_24bytes()),
            32 => writer.put_bytes(&self.asan_runtime.blob_check_mem_32bytes()),
            48 => writer.put_bytes(&self.asan_runtime.blob_check_mem_48bytes()),
            64 => writer.put_bytes(&self.asan_runtime.blob_check_mem_64bytes()),
            _ => false,
        };
        */

        writer.put_pop_reg(X86Register::Rsi);
        writer.put_pop_reg(X86Register::Rdi);
        writer.put_lea_reg_reg_offset(X86Register::Rsp, X86Register::Rsp, redzone_size);
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn emit_shadow_check(
        &mut self,
        _address: u64,
        output: &StalkerOutput,
        basereg: capstone::RegId,
        indexreg: capstone::RegId,
        displacement: i32,
        width: u32,
        shift: Arm64Shift,
        extender: Arm64Extender,
    ) {
        let redzone_size = frida_gum_sys::GUM_RED_ZONE_SIZE as i32;
        let writer = output.writer();

        let basereg = self.writer_register(basereg);
        let indexreg = if indexreg.0 != 0 {
            Some(self.writer_register(indexreg))
        } else {
            None
        };

        if self.current_report_impl == 0
            || !writer.can_branch_directly_to(self.current_report_impl)
            || !writer.can_branch_directly_between(writer.pc() + 128, self.current_report_impl)
        {
            let after_report_impl = writer.code_offset() + 2;

            #[cfg(target_arch = "x86_64")]
            writer.put_jmp_near_label(after_report_impl);
            #[cfg(target_arch = "aarch64")]
            writer.put_b_label(after_report_impl);

            self.current_report_impl = writer.pc();

            #[cfg(unix)]
            writer.put_bytes(self.asan_runtime.blob_report());

            writer.put_label(after_report_impl);
        }
        //writer.put_brk_imm(1);

        // Preserve x0, x1:
        writer.put_stp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            -(16 + redzone_size) as i64,
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

            if let (Arm64Extender::ARM64_EXT_INVALID, Arm64Shift::Invalid) = (extender, shift) {
                writer.put_add_reg_reg_reg(
                    Aarch64Register::X0,
                    Aarch64Register::X0,
                    Aarch64Register::X1,
                );
            } else {
                let extender_encoding: i32 = match extender {
                    Arm64Extender::ARM64_EXT_UXTB => 0b000,
                    Arm64Extender::ARM64_EXT_UXTH => 0b001,
                    Arm64Extender::ARM64_EXT_UXTW => 0b010,
                    Arm64Extender::ARM64_EXT_UXTX => 0b011,
                    Arm64Extender::ARM64_EXT_SXTB => 0b100,
                    Arm64Extender::ARM64_EXT_SXTH => 0b101,
                    Arm64Extender::ARM64_EXT_SXTW => 0b110,
                    Arm64Extender::ARM64_EXT_SXTX => 0b111,
                    _ => -1,
                };
                let (shift_encoding, shift_amount): (i32, u32) = match shift {
                    Arm64Shift::Lsl(amount) => (0b00, amount),
                    Arm64Shift::Lsr(amount) => (0b01, amount),
                    Arm64Shift::Asr(amount) => (0b10, amount),
                    _ => (-1, 0),
                };

                if extender_encoding != -1 && shift_amount < 0b1000 {
                    // emit add extended register: https://developer.arm.com/documentation/ddi0602/latest/Base-Instructions/ADD--extended-register---Add--extended-register--
                    writer.put_bytes(
                        &(0x8b210000 | ((extender_encoding as u32) << 13) | (shift_amount << 10))
                            .to_le_bytes(),
                    );
                } else if shift_encoding != -1 {
                    writer.put_bytes(
                        &(0x8b010000 | ((shift_encoding as u32) << 22) | (shift_amount << 10))
                            .to_le_bytes(),
                    );
                } else {
                    panic!("extender: {:?}, shift: {:?}", extender, shift);
                }
            };
        }

        let displacement = displacement
            + if basereg == Aarch64Register::Sp {
                16 + redzone_size
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
        #[cfg(unix)]
        match width {
            1 => writer.put_bytes(&self.asan_runtime.blob_check_mem_byte()),
            2 => writer.put_bytes(&self.asan_runtime.blob_check_mem_halfword()),
            3 => writer.put_bytes(&self.asan_runtime.blob_check_mem_3bytes()),
            4 => writer.put_bytes(&self.asan_runtime.blob_check_mem_dword()),
            6 => writer.put_bytes(&self.asan_runtime.blob_check_mem_6bytes()),
            8 => writer.put_bytes(&self.asan_runtime.blob_check_mem_qword()),
            12 => writer.put_bytes(&self.asan_runtime.blob_check_mem_12bytes()),
            16 => writer.put_bytes(&self.asan_runtime.blob_check_mem_16bytes()),
            24 => writer.put_bytes(&self.asan_runtime.blob_check_mem_24bytes()),
            32 => writer.put_bytes(&self.asan_runtime.blob_check_mem_32bytes()),
            48 => writer.put_bytes(&self.asan_runtime.blob_check_mem_48bytes()),
            64 => writer.put_bytes(&self.asan_runtime.blob_check_mem_64bytes()),
            _ => false,
        };

        // Add the branch to report
        //writer.put_brk_imm(0x12);
        writer.put_branch_address(self.current_report_impl);

        match width {
            3 | 6 | 12 | 24 | 32 | 48 | 64 => {
                let msr_nvcz_x0: u32 = 0xd51b4200;
                writer.put_bytes(&msr_nvcz_x0.to_le_bytes());
            }
            _ => (),
        }

        // Restore x0, x1
        assert!(writer.put_ldp_reg_reg_reg_offset(
            Aarch64Register::X0,
            Aarch64Register::X1,
            Aarch64Register::Sp,
            16 + redzone_size as i64,
            IndexMode::PostAdjust,
        ));
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn instruction_width(&self, instr: &Insn, operands: &Vec<arch::ArchOperand>) -> u32 {
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

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn asan_is_interesting_instruction(
        &self,
        _address: u64,
        instr: &Insn,
    ) -> Result<
        (
            capstone::RegId,
            capstone::RegId,
            i32,
            u32,
            Arm64Shift,
            Arm64Extender,
        ),
        (),
    > {
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
                    self.instruction_width(instr, &operands),
                    arm64operand.shift,
                    arm64operand.ext,
                ));
            }
        }

        Err(())
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn asan_is_interesting_instruction(
        &self,
        _address: u64,
        instr: &Insn,
    ) -> Result<(RegId, u8, RegId, RegId, i32, i64), ()> {
        let operands = self
            .capstone
            .insn_detail(instr)
            .unwrap()
            .arch_detail()
            .operands();

        // Ignore lea instruction
        match instr.mnemonic().unwrap() {
            "lea" => return Err(()),
            _ => (),
        }


        for operand in operands {
            if let X86Operand(x86operand) = operand {
                if let X86OperandType::Mem(opmem) = x86operand.op_type {
                    let insn_id : X86Insn = instr.id().0.into();
                    println!(
                        "insn: {:#?} {:#?} width: {}, segment: {:#?}, base: {:#?}, index: {:#?}, scale: {}, disp: {}",
                        insn_id,
                        instr,
                        x86operand.size,
                        opmem.segment(),
                        opmem.base(),
                        opmem.index(),
                        opmem.scale(),
                        opmem.disp(),
                    );
                    if opmem.segment() != RegId(0) {
                        return Ok((
                            opmem.segment(),
                            x86operand.size,
                            opmem.base(),
                            opmem.index(),
                            opmem.scale(),
                            opmem.disp(),
                        ));
                    }

                }
            }
        }

        Err(())
    }

    #[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
    #[inline]
    /// Check if the current instruction is cmplog relevant one(any opcode which sets the flags)
    fn cmplog_is_interesting_instruction(
        &self,
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
            "cmp" | "ands" | "subs" | "adds" | "negs" | "ngcs" | "sbcs" | "bics" | "cls"
            | "cbz" | "tbz" | "tbnz" => (),
            _ => return Err(()),
        }
        let operands = self
            .capstone
            .insn_detail(instr)
            .unwrap()
            .arch_detail()
            .operands();

        // cbz - 1 operand, tbz - 3 operands
        let special_case = ["cbz", "tbz", "tbnz"].contains(&instr.mnemonic().unwrap());
        if operands.len() != 2 || !special_case {
            return Err(());
        }
        // cbz marked as special since there is only 1 operand
        let special_case = instr.mnemonic().unwrap() == "cbz";

        let operand1 = if let Arm64Operand(arm64operand) = operands.first().unwrap() {
            match arm64operand.op_type {
                Arm64OperandType::Reg(regid) => Some(CmplogOperandType::Regid(regid)),
                Arm64OperandType::Imm(val) => Some(CmplogOperandType::Imm(val as u64)),
                Arm64OperandType::Mem(opmem) => Some(CmplogOperandType::Mem(
                    opmem.base(),
                    opmem.index(),
                    opmem.disp(),
                    self.instruction_width(instr, &operands),
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
                            self.instruction_width(instr, &operands),
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

    #[inline]
    fn emit_coverage_mapping(&mut self, address: u64, output: &StalkerOutput) {
        let writer = output.writer();
        #[allow(clippy::cast_possible_wrap)] // gum redzone size is u32, we need an offset as i32.
        let redzone_size = frida_gum_sys::GUM_RED_ZONE_SIZE as i64;
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
            writer.put_lea_reg_reg_offset(X86Register::Rsp, X86Register::Rsp, -(redzone_size));
            writer.put_push_reg(X86Register::Rdi);
            writer.put_mov_reg_address(
                X86Register::Rdi,
                ((address >> 4) ^ (address << 8)) & (MAP_SIZE - 1) as u64,
            );
            writer.put_call_address(self.current_log_impl);
            writer.put_pop_reg(X86Register::Rdi);
            writer.put_lea_reg_reg_offset(X86Register::Rsp, X86Register::Rsp, redzone_size);
        }
        #[cfg(target_arch = "aarch64")]
        {
            writer.put_stp_reg_reg_reg_offset(
                Aarch64Register::Lr,
                Aarch64Register::X0,
                Aarch64Register::Sp,
                -(16 + redzone_size) as i64,
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
                16 + redzone_size as i64,
                IndexMode::PostAdjust,
            );
        }
    }
}
