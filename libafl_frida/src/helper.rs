use libafl::{
    bolts::{cli::FuzzerOptions, tuples::MatchFirstType},
    inputs::{HasTargetBytes, Input},
    Error,
};

#[cfg(unix)]
use libafl_targets::drcov::DrCovBasicBlock;

#[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
use crate::cmplog_rt::CmpLogRuntime;
use crate::coverage_rt::CoverageRuntime;
#[cfg(unix)]
use crate::{asan::asan_rt::AsanRuntime, drcov_rt::DrCovRuntime};
#[cfg(target_arch = "aarch64")]
use capstone::{
    arch::{self, BuildsCapstone},
    Capstone,
};
#[cfg(all(target_arch = "x86_64", unix))]
use capstone::{
    arch::{self, BuildsCapstone},
    Capstone,
};
use core::fmt::{self, Debug, Formatter};
#[cfg(unix)]
use frida_gum::CpuContext;

#[cfg(unix)]
use frida_gum::instruction_writer::InstructionWriter;
use frida_gum::{stalker::Transformer, Gum, Module, ModuleDetails, ModuleMap, PageProtection};
#[cfg(unix)]
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use rangemap::RangeMap;

#[cfg(any(target_vendor = "apple"))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANON;
#[cfg(not(any(target_vendor = "apple", target_os = "windows")))]
const ANONYMOUS_FLAG: MapFlags = MapFlags::MAP_ANONYMOUS;

/// The Runtime trait
pub trait FridaRuntime: 'static + Debug {
    /// Initialization
    fn init(
        &mut self,
        gum: &Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        modules_to_instrument: &[&str],
    );

    /// Method called before execution
    fn pre_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error>;

    /// Method called after execution
    fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error>;
}

/// The tuple for Frida Runtime
pub trait FridaRuntimeTuple: MatchFirstType + Debug {
    /// Initialization
    fn init_all(
        &mut self,
        gum: &Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        modules_to_instrument: &[&str],
    );

    /// Method called before execution
    fn pre_exec_all<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error>;

    /// Method called after execution
    fn post_exec_all<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error>;
}

impl FridaRuntimeTuple for () {
    fn init_all(
        &mut self,
        _gum: &Gum,
        _ranges: &RangeMap<usize, (u16, String)>,
        _modules_to_instrument: &[&str],
    ) {
    }
    fn pre_exec_all<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
        Ok(())
    }
    fn post_exec_all<I: Input + HasTargetBytes>(&mut self, _input: &I) -> Result<(), Error> {
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
    options: &'a FuzzerOptions,
    runtimes: RT,
}

impl<RT> Debug for FridaInstrumentationHelper<'_, RT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut dbg_me = f.debug_struct("FridaInstrumentationHelper");
        dbg_me
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
    pub fn new(gum: &'a Gum, options: &'a FuzzerOptions, runtimes: RT) -> Self {
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

        let mut modules_to_instrument = vec![options
            .harness
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .to_string()];
        modules_to_instrument.append(&mut options.libs_to_instrument.clone());
        let modules_to_instrument: Vec<&str> =
            modules_to_instrument.iter().map(AsRef::as_ref).collect();

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
            module_map: ModuleMap::new_from_names(&modules_to_instrument),
            options,
            runtimes,
        };

        if options.cmplog || options.asan || !options.disable_coverage {
            for (i, module) in helper.module_map.values().iter().enumerate() {
                let range = module.range();
                let start = range.base_address().0 as usize;
                // println!("start: {:x}", start);
                helper
                    .ranges
                    .insert(start..(start + range.size()), (i as u16, module.path()));
            }
            if !options.dont_instrument.is_empty() {
                for (module_name, offset) in options.dont_instrument.clone() {
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
                    #[cfg(unix)]
                    let instr_size = instr.bytes().len();
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
                            if let Some(rt) = helper.runtime_mut::<CoverageRuntime>() {
                                rt.emit_coverage_mapping(address, &output);
                            }

                            #[cfg(unix)]
                            if let Some(rt) = helper.runtime_mut::<DrCovRuntime>() {
                                instruction.put_callout(|context| {
                                    let real_address = rt.real_address_for_stalked(pc(&context));
                                    //let (range, (id, name)) = helper.ranges.get_key_value(&real_address).unwrap();
                                    //println!("{}:0x{:016x}", name, real_address - range.start);
                                    rt.drcov_basic_blocks.push(DrCovBasicBlock::new(
                                        real_address,
                                        real_address + instr_size,
                                    ));
                                });
                            }
                        }

                        #[cfg(unix)]
                        let res = if let Some(rt) = helper.runtime::<AsanRuntime>() {
                            rt.asan_is_interesting_instruction(&helper.capstone, address, instr)
                        } else {
                            None
                        };

                        #[cfg(all(target_arch = "x86_64", unix))]
                        if let Some((segment, width, basereg, indexreg, scale, disp)) = res {
                            if let Some(rt) = helper.runtime_mut::<AsanRuntime>() {
                                rt.emit_shadow_check(
                                    address, &output, segment, width, basereg, indexreg, scale,
                                    disp,
                                );
                            }
                        }

                        #[cfg(target_arch = "aarch64")]
                        if let Some((basereg, indexreg, displacement, width, shift, extender)) = res
                        {
                            if let Some(rt) = helper.runtime_mut::<AsanRuntime>() {
                                rt.emit_shadow_check(
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

                        #[cfg(all(feature = "cmplog", target_arch = "aarch64"))]
                        if let Some(rt) = helper.runtime::<CmpLogRuntime>() {
                            if let Ok((op1, op2, special_case)) = rt
                                .cmplog_is_interesting_instruction(&helper.capstone, address, instr)
                            {
                                //emit code that saves the relevant data in runtime(passes it to x0, x1)
                                rt.emit_comparison_handling(
                                    address,
                                    &output,
                                    op1,
                                    op2,
                                    special_case,
                                );
                            }
                        }

                        #[cfg(unix)]
                        if let Some(rt) = helper.runtime_mut::<AsanRuntime>() {
                            rt.add_stalked_address(
                                output.writer().pc() as usize - instr_size,
                                address as usize,
                            );
                        }

                        #[cfg(unix)]
                        if let Some(rt) = helper.runtime_mut::<DrCovRuntime>() {
                            rt.add_stalked_address(
                                output.writer().pc() as usize - instr_size,
                                address as usize,
                            );
                        }
                    }
                    instruction.keep();
                }
            });
            helper.transformer = Some(transformer);
            helper
                .runtimes
                .init_all(gum, &helper.ranges, &modules_to_instrument);
        }
        helper
    }

    /// Return the runtime
    pub fn runtime<R>(&self) -> Option<&R>
    where
        R: FridaRuntime,
    {
        self.runtimes.match_first_type::<R>()
    }

    /// Return the mutable runtime
    pub fn runtime_mut<R>(&mut self) -> Option<&mut R>
    where
        R: FridaRuntime,
    {
        self.runtimes.match_first_type_mut::<R>()
    }

    /// Returns ref to the Transformer
    pub fn transformer(&self) -> &Transformer<'a> {
        self.transformer.as_ref().unwrap()
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

    /// Method called before execution
    pub fn pre_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        self.runtimes.pre_exec_all(input)
    }

    /// Method called after execution
    pub fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        self.runtimes.post_exec_all(input)
    }

    /// If stalker is enabled
    pub fn stalker_enabled(&self) -> bool {
        self.options.cmplog || self.options.asan || !self.options.disable_coverage
    }

    /// Pointer to coverage map
    pub fn map_ptr_mut(&mut self) -> Option<*mut u8> {
        self.runtime_mut::<CoverageRuntime>()
            .map(CoverageRuntime::map_ptr_mut)
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
    pub fn options(&self) -> &FuzzerOptions {
        self.options
    }
}
