use core::fmt::{self, Debug, Formatter};
use std::{
    cell::{Ref, RefCell, RefMut},
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};

#[cfg(unix)]
use frida_gum::instruction_writer::InstructionWriter;
use frida_gum::{
    stalker::{StalkerIterator, StalkerOutput, Transformer},
    Gum, Module, ModuleDetails, ModuleMap, PageProtection,
};
use libafl::{
    inputs::{HasTargetBytes, Input},
    Error,
};
use libafl_bolts::{cli::FuzzerOptions, tuples::MatchFirstType};
use libafl_targets::drcov::DrCovBasicBlock;
#[cfg(unix)]
use nix::sys::mman::{mmap, MapFlags, ProtFlags};
use rangemap::RangeMap;
#[cfg(target_arch = "aarch64")]
use yaxpeax_arch::Arch;
#[cfg(all(target_arch = "aarch64", unix))]
use yaxpeax_arm::armv8::a64::{ARMv8, InstDecoder};
#[cfg(target_arch = "x86_64")]
use yaxpeax_x86::amd64::InstDecoder;

#[cfg(unix)]
use crate::asan::asan_rt::AsanRuntime;
#[cfg(feature = "cmplog")]
use crate::cmplog_rt::CmpLogRuntime;
use crate::{coverage_rt::CoverageRuntime, drcov_rt::DrCovRuntime};

#[cfg(target_vendor = "apple")]
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
        module_map: &Rc<ModuleMap>,
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
        module_map: &Rc<ModuleMap>,
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
        _module_map: &Rc<ModuleMap>,
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
        module_map: &Rc<ModuleMap>,
    ) {
        self.0.init(gum, ranges, module_map);
        self.1.init_all(gum, ranges, module_map);
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

/// Represents a range to be skipped for instrumentation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipRange {
    /// An absolute range
    Absolute(std::ops::Range<usize>),

    /// A range relative to the module with the given name
    ModuleRelative {
        /// The module name
        name: String,

        /// The address range
        range: std::ops::Range<usize>,
    },
}

/// Builder for [`FridaInstrumentationHelper`](FridaInstrumentationHelper)
pub struct FridaInstrumentationHelperBuilder {
    stalker_enabled: bool,
    disable_excludes: bool,
    #[allow(clippy::type_complexity)]
    instrument_module_predicate: Option<Box<dyn FnMut(&ModuleDetails) -> bool>>,
    skip_module_predicate: Box<dyn FnMut(&ModuleDetails) -> bool>,
    skip_ranges: Vec<SkipRange>,
}

impl FridaInstrumentationHelperBuilder {
    /// Create a new `FridaInstrumentationHelperBuilder`
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable or disable the Stalker
    ///
    /// Required for coverage collection, ASAN, and `CmpLog`.
    /// Enabled by default.
    #[must_use]
    pub fn enable_stalker(self, enabled: bool) -> Self {
        Self {
            stalker_enabled: enabled,
            ..self
        }
    }

    /// Disable excludes
    ///
    /// Don't use `stalker.exclude()`.
    /// See <https://github.com/AFLplusplus/LibAFL/issues/830>
    #[must_use]
    pub fn disable_excludes(self, disabled: bool) -> Self {
        Self {
            disable_excludes: disabled,
            ..self
        }
    }

    /// Modules for which the given predicate returns `true` will be instrumented.
    ///
    /// Can be specified multiple times; a module will be instrumented if _any_ of the given predicates match.
    /// [`skip_modules_if`](Self::skip_modules-if) will override these.
    ///
    /// # Example
    /// Instrument all modules in `/usr/lib` as well as `libfoo.so`:
    /// ```
    ///# use libafl_frida::helper::FridaInstrumentationHelperBuilder;
    /// let builder = FridaInstrumentationHelperBuilder::new()
    ///     .instrument_module_if(|module| module.name() == "libfoo.so")
    ///     .instrument_module_if(|module| module.path().starts_with("/usr/lib"));
    /// ```
    #[must_use]
    pub fn instrument_module_if<F: FnMut(&ModuleDetails) -> bool + 'static>(
        mut self,
        mut predicate: F,
    ) -> Self {
        let new = move |module: &_| match &mut self.instrument_module_predicate {
            Some(existing) => existing(module) || predicate(module),
            None => predicate(module),
        };
        Self {
            instrument_module_predicate: Some(Box::new(new)),
            ..self
        }
    }

    /// Modules for which the given predicate returns `true` will not be instrumented.
    ///
    /// Can be specified multiple times; a module will be skipped  if _any_ of the given predicates match.
    /// Overrides modules included using [`instrument_module_if`](Self::instrument_module_if).
    ///
    /// # Example
    /// Instrument all modules in `/usr/lib`, but exclude `libfoo.so`.
    ///
    /// ```
    ///# use libafl_frida::helper::FridaInstrumentationHelperBuilder;
    /// let builder = FridaInstrumentationHelperBuilder::new()
    ///     .instrument_module_if(|module| module.path().starts_with("/usr/lib"))
    ///     .skip_module_if(|module| module.name() == "libfoo.so");
    /// ```
    #[must_use]
    pub fn skip_module_if<F: FnMut(&ModuleDetails) -> bool + 'static>(
        mut self,
        mut predicate: F,
    ) -> Self {
        let new = move |module: &_| (self.skip_module_predicate)(module) || predicate(module);
        Self {
            skip_module_predicate: Box::new(new),
            ..self
        }
    }

    /// Skip a specific range
    #[must_use]
    pub fn skip_range(mut self, range: SkipRange) -> Self {
        self.skip_ranges.push(range);
        self
    }

    /// Skip a set of ranges
    #[must_use]
    pub fn skip_ranges<I: IntoIterator<Item = SkipRange>>(mut self, ranges: I) -> Self {
        self.skip_ranges.extend(ranges);
        self
    }

    /// Build a `FridaInstrumentationHelper`
    pub fn build<RT: FridaRuntimeTuple>(
        self,
        gum: &Gum,
        runtimes: RT,
    ) -> FridaInstrumentationHelper<'_, RT> {
        let Self {
            stalker_enabled,
            disable_excludes,
            mut instrument_module_predicate,
            mut skip_module_predicate,
            skip_ranges,
        } = self;

        let mut module_filter = Box::new(move |module| {
            if let Some(instrument_module_predicate) = &mut instrument_module_predicate {
                let skip = skip_module_predicate(&module);
                let should_instrument = instrument_module_predicate(&module);
                should_instrument && !skip
            } else {
                !skip_module_predicate(&module)
            }
        });
        let module_map = Rc::new(ModuleMap::new_with_filter(gum, &mut module_filter));

        let ranges = RangeMap::new();
        // Wrap ranges and runtimes in reference-counted refcells in order to move
        // these references both into the struct that we return and the transformer callback
        // that we pass to frida-gum.
        //
        // These moves MUST occur before the runtimes are init-ed
        let ranges = Rc::new(RefCell::new(ranges));
        let runtimes = Rc::new(RefCell::new(runtimes));

        if stalker_enabled {
            for (i, module) in module_map.values().iter().enumerate() {
                let range = module.range();
                let start = range.base_address().0 as usize;
                ranges
                    .borrow_mut()
                    .insert(start..(start + range.size()), (i as u16, module.path()));
            }
            for skip in skip_ranges {
                match skip {
                    SkipRange::Absolute(range) => ranges.borrow_mut().remove(range),
                    SkipRange::ModuleRelative { name, range } => {
                        let module_details = ModuleDetails::with_name(name).unwrap();
                        let lib_start = module_details.range().base_address().0 as usize;
                        ranges
                            .borrow_mut()
                            .remove((lib_start + range.start)..(lib_start + range.end));
                    }
                }
            }
            runtimes
                .borrow_mut()
                .init_all(gum, &ranges.borrow(), &module_map);
        }

        let transformer = FridaInstrumentationHelper::build_transformer(gum, &ranges, &runtimes);

        #[cfg(unix)]
        FridaInstrumentationHelper::<'_, RT>::workaround_gum_allocate_near();

        FridaInstrumentationHelper {
            transformer,
            ranges,
            runtimes,
            stalker_enabled,
            disable_excludes,
        }
    }
}

impl Debug for FridaInstrumentationHelperBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut dbg_me = f.debug_struct("FridaInstrumentationHelper");
        dbg_me
            .field("stalker_enabled", &self.stalker_enabled)
            .field("instrument_module_predicate", &"<closure>")
            .field("skip_module_predicate", &"<closure>")
            .field("skip_ranges", &self.skip_ranges)
            .field("disable_excludes", &self.disable_excludes);
        dbg_me.finish()
    }
}

impl Default for FridaInstrumentationHelperBuilder {
    fn default() -> Self {
        Self {
            stalker_enabled: true,
            disable_excludes: true,
            instrument_module_predicate: None,
            skip_module_predicate: Box::new(|module| {
                // Skip the instrumentation module to avoid recursion.
                let range = module.range();
                let start = range.base_address().0 as usize;
                let range = start..(start + range.size());
                range.contains(&(Self::new as usize))
            }),
            skip_ranges: Vec::new(),
        }
    }
}

/// An helper that feeds `FridaInProcessExecutor` with edge-coverage instrumentation
pub struct FridaInstrumentationHelper<'a, RT: 'a> {
    transformer: Transformer<'a>,
    ranges: Rc<RefCell<RangeMap<usize, (u16, String)>>>,
    runtimes: Rc<RefCell<RT>>,
    stalker_enabled: bool,
    pub(crate) disable_excludes: bool,
}

impl<RT> Debug for FridaInstrumentationHelper<'_, RT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut dbg_me = f.debug_struct("FridaInstrumentationHelper");
        dbg_me
            .field("ranges", &self.ranges)
            .field("module_map", &"<ModuleMap>")
            .field("stalker_enabled", &self.stalker_enabled);
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

fn pathlist_contains_module<I, P>(list: I, module: &ModuleDetails) -> bool
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let module_name = module.name();
    let module_path = PathBuf::from(module.path());
    let canonicalized_module_path = fs::canonicalize(&module_path).ok();
    list.into_iter().any(|path| {
        let path = path.as_ref();

        path == Path::new(&module_name)
            || path == module_path
            || (canonicalized_module_path.is_some()
                && fs::canonicalize(path).ok() == canonicalized_module_path)
    })
}

impl<'a> FridaInstrumentationHelper<'a, ()> {
    /// Create a builder to initialize a `FridaInstrumentationHelper`.
    ///
    /// See the documentation of [`FridaInstrumentationHelperBuilder`](FridaInstrumentationHelperBuilder)
    /// for more details.
    pub fn builder() -> FridaInstrumentationHelperBuilder {
        FridaInstrumentationHelperBuilder::default()
    }
}

/// The implementation of the [`FridaInstrumentationHelper`]
impl<'a, RT> FridaInstrumentationHelper<'a, RT>
where
    RT: FridaRuntimeTuple + 'a,
{
    /// Constructor function to create a new [`FridaInstrumentationHelper`], given CLI Options.
    #[must_use]
    pub fn new<'b>(gum: &'a Gum, options: &'b FuzzerOptions, runtimes: RT) -> Self {
        let harness = options.harness.clone();
        let libs_to_instrument = options
            .libs_to_instrument
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        FridaInstrumentationHelper::builder()
            .enable_stalker(options.cmplog || options.asan || !options.disable_coverage)
            .disable_excludes(options.disable_excludes)
            .instrument_module_if(move |module| pathlist_contains_module(&harness, module))
            .instrument_module_if(move |module| {
                pathlist_contains_module(&libs_to_instrument, module)
            })
            .skip_ranges(options.dont_instrument.iter().map(|(name, offset)| {
                SkipRange::ModuleRelative {
                    name: name.clone(),
                    range: *offset..*offset + 4,
                }
            }))
            .build(gum, runtimes)
    }

    #[allow(clippy::too_many_lines)]
    fn build_transformer(
        gum: &'a Gum,
        ranges: &Rc<RefCell<RangeMap<usize, (u16, String)>>>,
        runtimes: &Rc<RefCell<RT>>,
    ) -> Transformer<'a> {
        let ranges = Rc::clone(ranges);
        let runtimes = Rc::clone(runtimes);

        #[cfg(target_arch = "x86_64")]
        let decoder = InstDecoder::minimal();

        #[cfg(target_arch = "aarch64")]
        let decoder = <ARMv8 as Arch>::Decoder::default();

        Transformer::from_callback(gum, move |basic_block, output| {
            Self::transform(basic_block, &output, &ranges, &runtimes, decoder);
        })
    }

    fn transform(
        basic_block: StalkerIterator,
        output: &StalkerOutput,
        ranges: &Rc<RefCell<RangeMap<usize, (u16, String)>>>,
        runtimes: &Rc<RefCell<RT>>,
        decoder: InstDecoder,
    ) {
        let mut first = true;
        let mut basic_block_start = 0;
        let mut basic_block_size = 0;
        for instruction in basic_block {
            let instr = instruction.instr();
            let instr_size = instr.bytes().len();
            let address = instr.address();
            // log::trace!("block @ {:x} transformed to {:x}", address, output.writer().pc());

            if ranges.borrow().contains_key(&(address as usize)) {
                let mut runtimes = (*runtimes).borrow_mut();
                if first {
                    first = false;
                    // log::info!(
                    //     "block @ {:x} transformed to {:x}",
                    //     address,
                    //     output.writer().pc()
                    // );
                    if let Some(rt) = runtimes.match_first_type_mut::<CoverageRuntime>() {
                        rt.emit_coverage_mapping(address, output);
                    }

                    if let Some(_rt) = runtimes.match_first_type_mut::<DrCovRuntime>() {
                        basic_block_start = address;
                    }
                }

                #[cfg(unix)]
                let res = if let Some(_rt) = runtimes.match_first_type_mut::<AsanRuntime>() {
                    AsanRuntime::asan_is_interesting_instruction(decoder, address, instr)
                } else {
                    None
                };

                #[cfg(all(target_arch = "x86_64", unix))]
                if let Some(details) = res {
                    if let Some(rt) = runtimes.match_first_type_mut::<AsanRuntime>() {
                        rt.emit_shadow_check(
                            address, output, details.0, details.1, details.2, details.3, details.4,
                        );
                    }
                }

                #[cfg(target_arch = "aarch64")]
                if let Some((basereg, indexreg, displacement, width, shift)) = res {
                    if let Some(rt) = runtimes.match_first_type_mut::<AsanRuntime>() {
                        rt.emit_shadow_check(
                            address,
                            output,
                            basereg,
                            indexreg,
                            displacement,
                            width,
                            shift,
                        );
                    }
                }

                #[cfg(all(
                    feature = "cmplog",
                    any(target_arch = "aarch64", target_arch = "x86_64")
                ))]
                if let Some(rt) = runtimes.match_first_type_mut::<CmpLogRuntime>() {
                    if let Some((op1, op2, shift, special_case)) =
                        CmpLogRuntime::cmplog_is_interesting_instruction(decoder, address, instr)
                    //change this as well
                    {
                        //emit code that saves the relevant data in runtime(passes it to x0, x1)
                        rt.emit_comparison_handling(
                            address,
                            output,
                            &op1,
                            &op2,
                            &shift,
                            &special_case,
                        );
                    }
                }

                #[cfg(unix)]
                if let Some(rt) = runtimes.match_first_type_mut::<AsanRuntime>() {
                    rt.add_stalked_address(
                        output.writer().pc() as usize - instr_size,
                        address as usize,
                    );
                }

                if let Some(_rt) = runtimes.match_first_type_mut::<DrCovRuntime>() {
                    basic_block_size += instr_size;
                }
            }
            instruction.keep();
        }
        if basic_block_size != 0 {
            if let Some(rt) = runtimes.borrow_mut().match_first_type_mut::<DrCovRuntime>() {
                log::trace!("{basic_block_start:#016X}:{basic_block_size:X}");
                rt.drcov_basic_blocks.push(DrCovBasicBlock::new(
                    basic_block_start as usize,
                    basic_block_start as usize + basic_block_size,
                ));
            }
        }
    }

    /*
    /// Return the runtime
    pub fn runtime<R>(&self) -> Option<&R>
    where
        R: FridaRuntime,
    {
        self.runtimes.borrow().match_first_type::<R>()
    }

    /// Return the mutable runtime
    pub fn runtime_mut<R>(&mut self) -> Option<&mut R>
    where
        R: FridaRuntime,
    {
        (*self.runtimes).borrow_mut().match_first_type_mut::<R>()
    }
    */

    // workaround frida's frida-gum-allocate-near bug:
    #[cfg(unix)]
    fn workaround_gum_allocate_near() {
        use std::fs::File;

        unsafe {
            for _ in 0..512 {
                mmap::<File>(
                    None,
                    std::num::NonZeroUsize::new_unchecked(128 * 1024),
                    ProtFlags::PROT_NONE,
                    ANONYMOUS_FLAG | MapFlags::MAP_PRIVATE | MapFlags::MAP_NORESERVE,
                    None,
                    0,
                )
                .expect("Failed to map dummy regions for frida workaround");
                mmap::<File>(
                    None,
                    std::num::NonZeroUsize::new_unchecked(4 * 1024 * 1024),
                    ProtFlags::PROT_NONE,
                    ANONYMOUS_FLAG | MapFlags::MAP_PRIVATE | MapFlags::MAP_NORESERVE,
                    None,
                    0,
                )
                .expect("Failed to map dummy regions for frida workaround");
            }
        }
    }

    /// Returns ref to the Transformer
    pub fn transformer(&self) -> &Transformer<'a> {
        &self.transformer
    }

    /// Initialize all
    pub fn init(
        &mut self,
        gum: &'a Gum,
        ranges: &RangeMap<usize, (u16, String)>,
        module_map: &Rc<ModuleMap>,
    ) {
        (*self.runtimes)
            .borrow_mut()
            .init_all(gum, ranges, module_map);
    }

    /// Method called before execution
    pub fn pre_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        (*self.runtimes).borrow_mut().pre_exec_all(input)
    }

    /// Method called after execution
    pub fn post_exec<I: Input + HasTargetBytes>(&mut self, input: &I) -> Result<(), Error> {
        (*self.runtimes).borrow_mut().post_exec_all(input)
    }

    /// If stalker is enabled
    pub fn stalker_enabled(&self) -> bool {
        self.stalker_enabled
    }

    /// Pointer to coverage map
    pub fn map_mut_ptr(&mut self) -> Option<*mut u8> {
        (*self.runtimes)
            .borrow_mut()
            .match_first_type_mut::<CoverageRuntime>()
            .map(CoverageRuntime::map_mut_ptr)
    }

    /// Ranges
    pub fn ranges(&self) -> Ref<RangeMap<usize, (u16, String)>> {
        self.ranges.borrow()
    }

    /// Mutable ranges
    pub fn ranges_mut(&mut self) -> RefMut<RangeMap<usize, (u16, String)>> {
        (*self.ranges).borrow_mut()
    }
}
