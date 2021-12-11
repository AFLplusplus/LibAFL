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

#[cfg(all(target_arch = "x86_64", unix))]
use capstone::{
    arch::{self, x86::X86OperandType, ArchOperand::X86Operand, BuildsCapstone},
    Capstone, Insn, RegId,
};

#[cfg(target_arch = "aarch64")]
use num_traits::cast::FromPrimitive;

#[cfg(target_arch = "aarch64")]
use frida_gum::instruction_writer::{Aarch64Register, IndexMode};
use frida_gum::{
    instruction_writer::InstructionWriter,
    stalker::{StalkerOutput, Transformer},
    ModuleDetails, ModuleMap,
};

#[cfg(unix)]
use frida_gum::CpuContext;

use frida_gum::{Gum, Module, PageProtection};

use rangemap::RangeMap;

#[cfg(unix)]
use nix::sys::mman::{mmap, MapFlags, ProtFlags};

#[cfg(unix)]
use crate::{asan::asan_rt::AsanRuntime, FridaOptions};

#[cfg(windows)]
use crate::FridaOptions;

use crate::coverage_rt::CoverageRuntime;

#[cfg(feature = "cmplog")]
use crate::cmplog_rt::CmpLogRuntime;

#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
enum CmplogOperandType {
    Regid(capstone::RegId),
    Imm(u64),
    Cimm(u64),
    Mem(capstone::RegId, capstone::RegId, i32, u32),
}

enum SpecialCmpLogCase {
    Tbz,
    Tbnz,
}

#[cfg(any(target_vendor = "apple"))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANON;
#[cfg(not(any(target_vendor = "apple", target_os = "windows")))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANONYMOUS;

/// An helper that feeds `FridaInProcessExecutor` with user-supplied instrumentation
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
    fn map_ptr_mut(&mut self) -> *mut u8;

    fn ranges(&self) -> &RangeMap<usize, (u16, String)>;
}

/// An helper that feeds `FridaInProcessExecutor` with edge-coverage instrumentation
pub struct FridaInstrumentationHelper<'a> {
    coverage_rt: CoverageRuntime,
    /// Transformer that has to be passed to FridaInProcessExecutor
    transformer: Option<Transformer<'a>>,
    #[cfg(unix)]
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

    #[cfg(not(unix))]
    fn pre_exec<I: Input + HasTargetBytes>(&mut self, _input: &I) {}

    #[cfg(unix)]
    fn pre_exec<I: Input + HasTargetBytes>(&mut self, input: &I) {
        let target_bytes = input.target_bytes();
        let slice = target_bytes.as_slice();
        //println!("target_bytes: {:#x}: {:02x?}", slice.as_ptr() as usize, slice);
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

        #[cfg(unix)]
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

    fn map_ptr_mut(&mut self) -> *mut u8 {
        self.coverage_rt.map_ptr_mut()
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

#[cfg(target_arch = "aarch64")]
fn pc(context: &CpuContext) -> usize {
    context.pc() as usize
}

#[cfg(all(target_arch = "x86_64", unix))]
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
            coverage_rt: CoverageRuntime::new(),
            transformer: None,
            #[cfg(target_arch = "aarch64")]
            capstone: Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build()
                .expect("Failed to create Capstone object"),
            #[cfg(all(target_arch = "x86_64", unix))]
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
                // println!("start: {:x}", start);
                helper
                    .ranges
                    .insert(start..(start + range.size()), (i as u16, module.path()));
            }
            if let Some(suppressed_specifiers) = helper.options().dont_instrument_locations() {
                for (module_name, offset) in suppressed_specifiers {
                    let module_details = ModuleDetails::with_name(module_name).unwrap();
                    let lib_start = module_details.range().base_address().0 as usize;
                    // println!("removing address: {:#x}", lib_start + offset);
                    helper
                        .ranges
                        .remove((lib_start + offset)..(lib_start + offset + 4));
                }
            }

            if helper.options().drcov_enabled() {
                std::fs::create_dir_all("./coverage")
                    .expect("failed to create directory for coverage files");
            }

            if helper.options().coverage_enabled() {
                helper.coverage_rt.init();
            }

            let transformer = Transformer::from_callback(gum, |basic_block, output| {
                let mut first = true;
                for instruction in basic_block {
                    let instr = instruction.instr();
                    let address = instr.address();
                    // println!("block @ {:x} transformed to {:x}", address, output.writer().pc());
                    /*
                    println!(
                        "address: {:x} contains: {:?}",
                        address,
                        helper.ranges.contains_key(&(address as usize))
                    );
                    */
                    // println!("Ranges: {:#?}", helper.ranges);
                    if helper.ranges.contains_key(&(address as usize)) {
                        if first {
                            first = false;
                            // println!("block @ {:x} transformed to {:x}", address, output.writer().pc());
                            if helper.options().coverage_enabled() {
                                helper.coverage_rt.emit_coverage_mapping(address, &output);
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
                            #[cfg(all(target_arch = "x86_64", unix))]
                            if let Ok((segment, width, basereg, indexreg, scale, disp)) = helper
                                .asan_runtime
                                .asan_is_interesting_instruction(&helper.capstone, address, instr)
                            {
                                helper.asan_runtime.emit_shadow_check(
                                    address, &output, segment, width, basereg, indexreg, scale,
                                    disp,
                                );
                            }
                            #[cfg(target_arch = "aarch64")]
                            if let Ok((basereg, indexreg, displacement, width, shift, extender)) =
                                helper.asan_runtime.asan_is_interesting_instruction(
                                    &helper.capstone,
                                    address,
                                    instr,
                                )
                            {
                                helper.asan_runtime.emit_shadow_check(
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
            "cmp" | "ands" | "subs" | "adds" | "negs" | "ngcs" | "sbcs" | "bics" | "cbz"
            | "cbnz" | "tbz" | "tbnz" | "adcs" => (),
            _ => return Err(()),
        }
        let mut operands = self
            .capstone
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
}
