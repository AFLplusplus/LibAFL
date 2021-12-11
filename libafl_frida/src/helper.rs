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

#[cfg(target_arch = "x86_64")]
use frida_gum::instruction_writer::X86Register;

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
                            if let Ok((op1, op2, special_case)) = helper
                                .cmplog_runtime
                                .cmplog_is_interesting_instruction(&helper.capstone, address, instr)
                            {
                                //emit code that saves the relevant data in runtime(passes it to x0, x1)
                                helper.cmplog_runtime.emit_comparison_handling(
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
    pub fn instruction_width(instr: &Insn, operands: &Vec<arch::ArchOperand>) -> u32 {
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
    pub fn writer_register(reg: capstone::RegId) -> Aarch64Register {
        let regint: u16 = reg.0;
        Aarch64Register::from_u32(regint as u32).unwrap()
    }

    // frida registers: https://docs.rs/frida-gum/0.4.0/frida_gum/instruction_writer/enum.X86Register.html
    // capstone registers: https://docs.rs/capstone-sys/0.14.0/capstone_sys/x86_reg/index.html
    #[cfg(all(target_arch = "x86_64", unix))]
    #[must_use]
    #[inline]
    #[allow(clippy::unused_self)]
    pub fn writer_register(reg: RegId) -> X86Register {
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
}
