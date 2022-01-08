use libafl::{
    bolts::tuples::MatchFirstType,
    inputs::{HasTargetBytes, Input},
    Error,
};
use libafl_targets::drcov::DrCovBasicBlock;

#[cfg(feature = "cmplog")]
use crate::cmplog_rt::CmpLogRuntime;
#[cfg(windows)]
use crate::FridaOptions;
#[cfg(unix)]
use crate::{asan::asan_rt::AsanRuntime, FridaOptions};
use crate::{coverage_rt::CoverageRuntime, drcov_rt::DrCovRuntime};
#[cfg(target_arch = "aarch64")]
use capstone::{
    arch::{self, arm64::Arm64OperandType, ArchOperand::Arm64Operand, BuildsCapstone},
    Capstone, Insn,
};
#[cfg(all(target_arch = "x86_64", unix))]
use capstone::{
    arch::{self, BuildsCapstone},
    Capstone,
};
use core::fmt::{self, Debug, Formatter};

#[cfg(unix)]
use frida_gum::CpuContext;
use frida_gum::{
    instruction_writer::InstructionWriter, stalker::Transformer, Gum, Module, ModuleDetails,
    ModuleMap, PageProtection,
};
#[cfg(unix)]
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
#[cfg(target_arch = "aarch64")]
use num_traits::cast::FromPrimitive;
use rangemap::RangeMap;

#[cfg(any(target_vendor = "apple"))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANON;
#[cfg(not(any(target_vendor = "apple", target_os = "windows")))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANONYMOUS;

pub trait FridaRuntime: 'static + Debug {
    fn init(
        &mut self,
        gum: &Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        modules_to_instrument: &[&str],
    );

    fn pre_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error>;

    fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error>;
}

pub trait FridaRuntimeTuple: MatchFirstType + Debug {
    fn init_all(
        &mut self,
        gum: &Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        modules_to_instrument: &[&str],
    );

    fn pre_exec_all<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error>;

    fn post_exec_all<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error>;
}

impl FridaRuntimeTuple for () {
    fn init_all(
        &mut self,
        gum: &Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        modules_to_instrument: &[&str],
    ) {
    }
    fn pre_exec_all<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        Ok(())
    }
    fn post_exec_all<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail> FridaRuntimeTuple for (Head, Tail)
where
    Head: FridaRuntime,
    Tail: FridaRuntimeTuple,
{
    fn init_all(
        &mut self,
        gum: &Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        modules_to_instrument: &[&str],
    ) {
        self.0.init(gum, ranges, modules_to_instrument);
        self.1.init_all(gum, ranges, modules_to_instrument);
    }

    fn pre_exec_all<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        self.0.pre_exec(input)?;
        self.1.pre_exec_all(input)
    }

    fn post_exec_all<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        self.0.post_exec(input)?;
        self.1.post_exec_all(input)
    }
}

/// An helper that feeds `FridaInProcessExecutor` with edge-coverage instrumentation
pub struct FridaInstrumentationHelper<'a, RT> {
    /// Transformer that has to be passed to FridaInProcessExecutor
    transformer: Option<Transformer<'a>>,
    #[cfg(unix)]
    capstone: Capstone,
    ranges: RangeMap<usize, (u16, String)>,
    module_map: ModuleMap,
    options: &'a FridaOptions,
    runtimes: RT,
}

impl<RT> Debug for FridaInstrumentationHelper<'_, RT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut dbg_me = f.debug_struct("FridaInstrumentationHelper");
        dbg_me
            .field("capstone", &self.capstone)
            .field("ranges", &self.ranges)
            .field("module_map", &"<ModuleMap>")
            .field("options", &self.options);
        dbg_me.finish()
    }
}

/// Helper function to get the size of a module's CODE section from frida
#[must_use]
pub fn get_module_size(module_name: &str) -> usize {
    let mut code_size = 0;
    let code_size_ref = &mut code_size;
    Module::enumerate_ranges(module_name, PageProtection::ReadExecute, move |details| {
        *code_size_ref = details.memory_range().size();
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
impl<'a, RT> FridaInstrumentationHelper<'a, RT>
where
    RT: FridaRuntimeTuple,
{
    /// Constructor function to create a new [`FridaInstrumentationHelper`], given a `module_name`.
    #[allow(clippy::too_many_lines)]
    #[must_use]
    pub fn new(
        gum: &'a Gum,
        options: &'a FridaOptions,
        _harness_module_name: &str,
        modules_to_instrument: &'a [&str],
        runtimes: RT,
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
            ranges: RangeMap::new(),
            module_map: ModuleMap::new_from_names(modules_to_instrument),
            options,
            runtimes,
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

            let transformer = Transformer::from_callback(gum, |basic_block, output| {
                let mut first = true;
                for instruction in basic_block {
                    let instr = instruction.instr();
                    let address = instr.address();
                    //println!("block @ {:x} transformed to {:x}", address, output.writer().pc());

                    //println!(
                    //"address: {:x} contains: {:?}",
                    //address,
                    //helper.ranges.contains_key(&(address as usize))
                    //);

                    // println!("Ranges: {:#?}", helper.ranges);
                    if helper.ranges.contains_key(&(address as usize)) {
                        if first {
                            first = false;
                            //println!("block @ {:x} transformed to {:x}", address, output.writer().pc());
                            if let Some(rt) = helper.coverage_runtime() {
                                rt.emit_coverage_mapping(address, &output);
                            }
                            #[cfg(unix)]
                            if helper.options().drcov_enabled() {
                                instruction.put_callout(|context| {
                                    let real_address =
                                        helper.asan_runtime.real_address_for_stalked(pc(&context));
                                    //let (range, (id, name)) = helper.ranges.get_key_value(&real_address).unwrap();
                                    //println!("{}:0x{:016x}", name, real_address - range.start);
                                    helper
                                        .drcov_runtime
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
        }
        helper
    }

    pub fn coverage_runtime(&self) -> Option<&CoverageRuntime> {
        self.runtimes.match_first_type::<CoverageRuntime>()
    }

    pub fn coverage_runtime_mut(&mut self) -> Option<&mut CoverageRuntime> {
        self.runtimes.match_first_type_mut::<CoverageRuntime>()
    }

    #[cfg(unix)]
    pub fn asan_runtime(&self) -> Option<&AsanRuntime> {
        self.runtimes.match_first_type::<AsanRuntime>()
    }

    #[cfg(unix)]
    pub fn asan_runtime_mut(&mut self) -> Option<&mut AsanRuntime> {
        self.runtimes.match_first_type_mut::<AsanRuntime>()
    }

    pub fn drcov_runtime(&self) -> Option<&DrCovRuntime> {
        self.runtimes.match_first_type::<DrCovRuntime>()
    }

    pub fn drcov_runtime_mut(&mut self) -> Option<&mut DrCovRuntime> {
        self.runtimes.match_first_type_mut::<DrCovRuntime>()
    }

    #[cfg(feature = "cmplog")]
    pub fn cmplog_runtime(&self) -> Option<&CmpLogRuntime> {
        self.runtimes.match_first_type::<CmpLogRuntime>()
    }

    #[cfg(feature = "cmplog")]
    pub fn cmplog_runtime_mut(&mut self) -> Option<&mut CmpLogRuntime> {
        self.runtime.match_first_type_mut::<CmpLogRuntime>()
    }

    /// Returns ref to the Transformer
    pub fn transformer(&self) -> &Transformer<'a> {
        self.transformer.as_ref().unwrap()
    }

    /// Register the current thread with the [`FridaInstrumentationHelper`]
    #[cfg(unix)]
    pub fn register_thread(&mut self) {
        self.asan_runtime.register_thread();
    }

    /// Initializa all
    pub fn init(
        &mut self,
        gum: &'a Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        modules_to_instrument: &'a [&str],
    ) {
        self.runtimes.init_all(gum, ranges, modules_to_instrument);
    }

    /// Pre_exec all
    pub fn pre_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        self.runtimes.pre_exec_all(input)
    }

    /// Post_exec all
    pub fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        self.runtimes.post_exec_all(input)
    }

    /// If stalker is enabled
    pub fn stalker_enabled(&self) -> bool {
        self.options.stalker_enabled()
    }

    /// Pointer to coverage map
    pub fn map_ptr_mut(&mut self) -> *mut u8 {
        self.coverage_rt.map_ptr_mut()
    }

    /// Ranges
    pub fn ranges(&self) -> &RangeMap<usize, (u16, String)> {
        &self.ranges
    }

    /// Mutable ranges
    pub fn ranges_mut(&mut self) -> &mut RangeMap<usize, (u16, String)> {
        &mut self.ranges
    }

    /// Return the ref to options
    #[inline]
    pub fn options(&self) -> &FridaOptions {
        self.options
    }
}
