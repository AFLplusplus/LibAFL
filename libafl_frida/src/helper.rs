use alloc::rc::Rc;
use core::{
    any::TypeId,
    cell::{Ref, RefCell, RefMut},
    ffi::CStr,
    fmt::{self, Debug, Formatter},
};
use std::{
    fs::{self, read_to_string},
    path::{Path, PathBuf},
};

use frida_gum::{
    Backend, Gum, Module, ModuleMap, Script,
    instruction_writer::InstructionWriter,
    stalker::{StalkerIterator, StalkerOutput, Transformer},
};
use frida_gum_sys::gchar;
use libafl::Error;
use libafl_bolts::{
    cli::{FridaScriptBackend, FuzzerOptions},
    tuples::MatchFirstType,
};
use libafl_targets::drcov::DrCovBasicBlock;
#[cfg(unix)]
use nix::sys::mman::{MapFlags, ProtFlags, mmap_anonymous};
use rangemap::RangeMap;
#[cfg(target_arch = "aarch64")]
use yaxpeax_arch::Arch;
#[cfg(all(target_arch = "aarch64", unix))]
use yaxpeax_arm::armv8::a64::{ARMv8, InstDecoder};
#[cfg(target_arch = "x86_64")]
use yaxpeax_x86::amd64::InstDecoder;

#[cfg(feature = "cmplog")]
use crate::cmplog_rt::CmpLogRuntime;
use crate::{asan::asan_rt::AsanRuntime, coverage_rt::CoverageRuntime, drcov_rt::DrCovRuntime};

/// The Runtime trait
pub trait FridaRuntime: 'static + Debug + core::any::Any {
    /// Initialization
    fn init(
        &mut self,
        gum: &Gum,
        ranges: &RangeMap<u64, (u16, String)>,
        module_map: &Rc<ModuleMap>,
    );
    /// Deinitialization
    fn deinit(&mut self, gum: &Gum);

    /// Method called before execution
    fn pre_exec(&mut self, input_bytes: &[u8]) -> Result<(), Error>;

    /// Method called after execution
    fn post_exec(&mut self, input_bytes: &[u8]) -> Result<(), Error>;
}

/// Use the runtime if closure evaluates to true
pub struct IfElseRuntime<CB, FR1, FR2> {
    closure: CB,
    if_runtimes: FR1,
    else_runtimes: FR2,
}

impl<CB, FR1, FR2> Debug for IfElseRuntime<CB, FR1, FR2>
where
    FR1: Debug,
    FR2: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.if_runtimes, f)?;
        Debug::fmt(&self.else_runtimes, f)?;
        Ok(())
    }
}
impl<CB, FR1, FR2> IfElseRuntime<CB, FR1, FR2> {
    /// Constructor for this conditionally enabled runtime
    pub fn new(closure: CB, if_runtimes: FR1, else_runtimes: FR2) -> Self {
        Self {
            closure,
            if_runtimes,
            else_runtimes,
        }
    }
}

impl<CB, FR1, FR2> FridaRuntime for IfElseRuntime<CB, FR1, FR2>
where
    CB: FnMut() -> Result<bool, Error> + 'static,
    FR1: FridaRuntimeTuple + 'static,
    FR2: FridaRuntimeTuple + 'static,
{
    fn init(
        &mut self,
        gum: &Gum,
        ranges: &RangeMap<u64, (u16, String)>,
        module_map: &Rc<ModuleMap>,
    ) {
        if (self.closure)().unwrap() {
            self.if_runtimes.init_all(gum, ranges, module_map);
        } else {
            self.else_runtimes.init_all(gum, ranges, module_map);
        }
    }

    fn deinit(&mut self, gum: &Gum) {
        if (self.closure)().unwrap() {
            self.if_runtimes.deinit_all(gum);
        } else {
            self.else_runtimes.deinit_all(gum);
        }
    }

    fn pre_exec(&mut self, input_bytes: &[u8]) -> Result<(), Error> {
        if (self.closure)()? {
            self.if_runtimes.pre_exec_all(input_bytes)
        } else {
            self.else_runtimes.pre_exec_all(input_bytes)
        }
    }

    fn post_exec(&mut self, input_bytes: &[u8]) -> Result<(), Error> {
        if (self.closure)()? {
            self.if_runtimes.post_exec_all(input_bytes)
        } else {
            self.else_runtimes.post_exec_all(input_bytes)
        }
    }
}
/// The tuple for Frida Runtime
pub trait FridaRuntimeTuple: MatchFirstType + Debug {
    /// Initialization
    fn init_all(
        &mut self,
        gum: &Gum,
        ranges: &RangeMap<u64, (u16, String)>,
        module_map: &Rc<ModuleMap>,
    );

    /// Deinitialization
    fn deinit_all(&mut self, gum: &Gum);

    /// Method called before execution
    fn pre_exec_all(&mut self, input_bytes: &[u8]) -> Result<(), Error>;

    /// Method called after execution
    fn post_exec_all(&mut self, input_bytes: &[u8]) -> Result<(), Error>;
}

impl FridaRuntimeTuple for () {
    fn init_all(
        &mut self,
        _gum: &Gum,
        _ranges: &RangeMap<u64, (u16, String)>,
        _module_map: &Rc<ModuleMap>,
    ) {
    }
    fn deinit_all(&mut self, _gum: &Gum) {}

    fn pre_exec_all(&mut self, _input_bytes: &[u8]) -> Result<(), Error> {
        Ok(())
    }
    fn post_exec_all(&mut self, _input_bytes: &[u8]) -> Result<(), Error> {
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
        ranges: &RangeMap<u64, (u16, String)>,
        module_map: &Rc<ModuleMap>,
    ) {
        self.0.init(gum, ranges, module_map);
        self.1.init_all(gum, ranges, module_map);
    }

    fn deinit_all(&mut self, gum: &Gum) {
        self.0.deinit(gum);
        self.1.deinit_all(gum);
    }

    fn pre_exec_all(&mut self, input_bytes: &[u8]) -> Result<(), Error> {
        self.0.pre_exec(input_bytes)?;
        self.1.pre_exec_all(input_bytes)
    }

    fn post_exec_all(&mut self, input_bytes: &[u8]) -> Result<(), Error> {
        self.0.post_exec(input_bytes)?;
        self.1.post_exec_all(input_bytes)
    }
}

/// Vector of `FridaRuntime`
#[derive(Debug)]
pub struct FridaRuntimeVec(pub Vec<Box<dyn FridaRuntime>>);

impl MatchFirstType for FridaRuntimeVec {
    fn match_first_type<T: 'static>(&self) -> Option<&T> {
        for member in &self.0 {
            if TypeId::of::<T>() == member.type_id() {
                let raw = core::ptr::from_ref::<dyn FridaRuntime>(&**member) as *const T;
                return unsafe { raw.as_ref() };
            }
        }

        None
    }

    fn match_first_type_mut<T: 'static>(&mut self) -> Option<&mut T> {
        for member in &mut self.0 {
            if TypeId::of::<T>() == member.type_id() {
                let raw = core::ptr::from_mut::<dyn FridaRuntime>(&mut **member) as *mut T;
                return unsafe { raw.as_mut() };
            }
        }

        None
    }
}

impl FridaRuntimeTuple for FridaRuntimeVec {
    fn init_all(
        &mut self,
        gum: &Gum,
        ranges: &RangeMap<u64, (u16, String)>,
        module_map: &Rc<ModuleMap>,
    ) {
        for runtime in &mut self.0 {
            runtime.init(gum, ranges, module_map);
        }
    }

    fn deinit_all(&mut self, gum: &Gum) {
        for runtime in &mut self.0 {
            runtime.deinit(gum);
        }
    }

    fn pre_exec_all(&mut self, input_bytes: &[u8]) -> Result<(), Error> {
        for runtime in &mut self.0 {
            runtime.pre_exec(input_bytes)?;
        }
        Ok(())
    }

    fn post_exec_all(&mut self, input_bytes: &[u8]) -> Result<(), Error> {
        for runtime in &mut self.0 {
            runtime.post_exec(input_bytes)?;
        }
        Ok(())
    }
}

/// Represents a range to be skipped for instrumentation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipRange {
    /// An absolute range
    Absolute(core::ops::Range<usize>),

    /// A range relative to the module with the given name
    ModuleRelative {
        /// The module name
        name: String,

        /// The address range
        range: core::ops::Range<usize>,
    },
}

/// Builder for [`FridaInstrumentationHelper`]
pub struct FridaInstrumentationHelperBuilder {
    stalker_enabled: bool,
    disable_excludes: bool,
    #[expect(clippy::type_complexity)]
    instrument_module_predicate: Option<Box<dyn FnMut(&Module) -> bool>>,
    skip_module_predicate: Box<dyn FnMut(&Module) -> bool>,
    skip_ranges: Vec<SkipRange>,
}

impl FridaInstrumentationHelperBuilder {
    /// Create a new [`FridaInstrumentationHelperBuilder`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a script
    ///
    /// See [`Script::new`] for details
    #[must_use]
    pub fn load_script<F: Fn(&str, &[u8])>(
        self,
        backend: FridaScriptBackend,
        path: &Path,
        callback: Option<F>,
    ) -> Self {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_else(|| panic!("Failed to get script file name from path: {path:?}"));
        let script_prefix = include_str!("script.js");
        let file_contents = read_to_string(path)
            .unwrap_or_else(|err| panic!("Failed to read script {path:?}: {err:?}"));
        let payload = script_prefix.to_string() + &file_contents;
        let gum = Gum::obtain();
        let backend = match backend {
            FridaScriptBackend::V8 => Backend::obtain_v8(&gum),
            FridaScriptBackend::QuickJS => Backend::obtain_qjs(&gum),
        };
        Script::load(&backend, name, payload, callback).unwrap();
        self
    }

    /// Enable or disable the [`Stalker`](https://frida.re/docs/stalker/)
    ///
    /// Required for all instrumentation, such as coverage collection, `ASan`, and `CmpLog`.
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
    /// # use libafl_frida::helper::FridaInstrumentationHelper;
    /// let builder = FridaInstrumentationHelper::builder()
    ///     .instrument_module_if(|module| module.name() == "libfoo.so")
    ///     .instrument_module_if(|module| module.path().starts_with("/usr/lib"));
    /// ```
    #[must_use]
    pub fn instrument_module_if<F: FnMut(&Module) -> bool + 'static>(
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
    /// # use libafl_frida::helper::FridaInstrumentationHelper;
    /// let builder = FridaInstrumentationHelper::builder()
    ///     .instrument_module_if(|module| module.path().starts_with("/usr/lib"))
    ///     .skip_module_if(|module| module.name() == "libfoo.so");
    /// ```
    #[must_use]
    pub fn skip_module_if<F: FnMut(&Module) -> bool + 'static>(mut self, mut predicate: F) -> Self {
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

    /// Build a [`FridaInstrumentationHelper`]
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
        let module_map = Rc::new(ModuleMap::new_with_filter(&mut module_filter));

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
                log::trace!(
                    "module: {:?} {:x}",
                    module.name(),
                    module.range().base_address().0 as usize
                );
                let range = module.range();
                let start = range.base_address().0 as u64;
                ranges.borrow_mut().insert(
                    start..(start + range.size() as u64),
                    (i as u16, module.path()),
                );
                for skip in &skip_ranges {
                    match skip {
                        SkipRange::Absolute(range) => ranges
                            .borrow_mut()
                            .remove(range.start as u64..range.end as u64),
                        SkipRange::ModuleRelative { name, range } => {
                            if name.eq(&module.name()) {
                                log::trace!("Skipping {name:?} {range:?}");
                                let module_details = Module::load(gum, &name.to_string());
                                let lib_start = module_details.range().base_address().0 as u64;
                                ranges.borrow_mut().remove(
                                    (lib_start + range.start as u64)
                                        ..(lib_start + range.end as u64),
                                );
                            }
                        }
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
            disable_excludes: false,
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
    ranges: Rc<RefCell<RangeMap<u64, (u16, String)>>>,
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

/// A callback function to test calling back from FRIDA's JavaScript scripting support
/// # Safety
/// This function receives a raw pointer to a C string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn test_function(message: *const gchar) {
    if let Ok(msg) = unsafe { CStr::from_ptr(message).to_str() } {
        println!("{msg}");
    }
}

fn pathlist_contains_module<I, P>(list: I, module: &Module) -> bool
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

impl FridaInstrumentationHelper<'_, ()> {
    /// Create a builder to initialize a [`FridaInstrumentationHelper`].
    ///
    /// See the documentation of [`FridaInstrumentationHelperBuilder`]
    /// for more details.
    #[must_use]
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
        let builder = FridaInstrumentationHelper::builder()
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
            }));

        let builder = if let Some(script) = &options.script {
            builder.load_script(
                options.backend.unwrap_or_default(),
                script,
                Some(FridaInstrumentationHelper::<RT>::script_callback),
            )
        } else {
            builder
        };
        builder.build(gum, runtimes)
    }

    fn script_callback(msg: &str, bytes: &[u8]) {
        println!("msg: {msg:}, bytes: {bytes:x?}");
    }

    fn build_transformer(
        gum: &'a Gum,
        ranges: &Rc<RefCell<RangeMap<u64, (u16, String)>>>,
        runtimes: &Rc<RefCell<RT>>,
    ) -> Transformer<'a> {
        let ranges = Rc::clone(ranges);
        let runtimes = Rc::clone(runtimes);

        #[cfg(target_arch = "x86_64")]
        let decoder = InstDecoder::default();

        #[cfg(target_arch = "aarch64")]
        let decoder = <ARMv8 as Arch>::Decoder::default();

        Transformer::from_callback(gum, move |basic_block, output| {
            Self::transform(basic_block, &output, &ranges, &runtimes, decoder);
        })
    }

    #[expect(clippy::too_many_lines)]
    fn transform(
        basic_block: StalkerIterator,
        output: &StalkerOutput,
        ranges: &Rc<RefCell<RangeMap<u64, (u16, String)>>>,
        runtimes_unborrowed: &Rc<RefCell<RT>>,
        decoder: InstDecoder,
    ) {
        let mut first = true;
        let mut basic_block_start = 0;
        let mut basic_block_size = 0;
        // let _guard = AsanInHookGuard::new(); // Ensure ASAN_IN_HOOK is set and reset
        for instruction in basic_block {
            let instr = instruction.instr();
            let instr_size = instr.bytes().len();
            let address = instr.address();
            // log::trace!("x - block @ {:x} transformed to {:x}", address, output.writer().pc());
            //the ASAN check needs to be done before the hook_rt check due to x86 insns such as call [mem]
            if ranges.borrow().contains_key(&address) {
                let mut runtimes = (*runtimes_unborrowed).borrow_mut();
                if first {
                    first = false;
                    log::trace!(
                        "block @ {:x} transformed to {:x}",
                        address,
                        output.writer().pc()
                    );
                    if let Some(rt) = runtimes.match_first_type_mut::<CoverageRuntime>() {
                        let start = output.writer().pc();
                        rt.emit_coverage_mapping(address, output);
                        log::trace!(
                            "emitted coverage info mapping for {:x} at {:x}-{:x}",
                            address,
                            start,
                            output.writer().pc()
                        );
                    }
                    if let Some(_rt) = runtimes.match_first_type_mut::<DrCovRuntime>() {
                        basic_block_start = address;
                    }
                }

                let res = if let Some(_rt) = runtimes.match_first_type_mut::<AsanRuntime>() {
                    AsanRuntime::asan_is_interesting_instruction(decoder, address, instr)
                } else {
                    None
                };

                #[cfg(target_arch = "x86_64")]
                if let Some(details) = res {
                    if let Some(rt) = runtimes.match_first_type_mut::<AsanRuntime>() {
                        let start = output.writer().pc();
                        rt.emit_shadow_check(
                            address,
                            output,
                            instr.bytes().len(),
                            details.0,
                            details.1,
                            details.2,
                            details.3,
                            details.4,
                        );
                        log::trace!(
                            "emitted shadow_check for {:x} at {:x}-{:x}",
                            address,
                            start,
                            output.writer().pc()
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
            if let Some(rt) = runtimes_unborrowed
                .borrow_mut()
                .match_first_type_mut::<DrCovRuntime>()
            {
                log::trace!("{basic_block_start:#016X}:{basic_block_size:X}");

                // We can maybe remove the `basic_block_size as u64`` cast in the future
                #[allow(trivial_numeric_casts)]
                rt.drcov_basic_blocks.push(DrCovBasicBlock::new(
                    basic_block_start,
                    basic_block_start + (basic_block_size as u64),
                ));
            }
        }
    }

    /// Clean up all runtimes
    pub fn deinit(&mut self, gum: &Gum) {
        (*self.runtimes).borrow_mut().deinit_all(gum);
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
        unsafe {
            for _ in 0..512 {
                mmap_anonymous(
                    None,
                    core::num::NonZeroUsize::new_unchecked(128 * 1024),
                    ProtFlags::PROT_NONE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_NORESERVE,
                )
                .expect("Failed to map dummy regions for frida workaround");
                mmap_anonymous(
                    None,
                    core::num::NonZeroUsize::new_unchecked(4 * 1024 * 1024),
                    ProtFlags::PROT_NONE,
                    MapFlags::MAP_PRIVATE | MapFlags::MAP_NORESERVE,
                )
                .expect("Failed to map dummy regions for frida workaround");
            }
        }
    }

    /// Returns ref to the Transformer
    #[must_use]
    pub fn transformer(&self) -> &Transformer<'a> {
        &self.transformer
    }

    /// Initialize all
    pub fn init(
        &mut self,
        gum: &'a Gum,
        ranges: &RangeMap<u64, (u16, String)>,
        module_map: &Rc<ModuleMap>,
    ) {
        (*self.runtimes)
            .borrow_mut()
            .init_all(gum, ranges, module_map);
    }

    /// Method called before execution
    pub fn pre_exec(&mut self, input_bytes: &[u8]) -> Result<(), Error> {
        (*self.runtimes).borrow_mut().pre_exec_all(input_bytes)
    }

    /// Method called after execution
    pub fn post_exec(&mut self, input_bytes: &[u8]) -> Result<(), Error> {
        (*self.runtimes).borrow_mut().post_exec_all(input_bytes)
    }

    /// If stalker is enabled
    #[must_use]
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
    #[must_use]
    pub fn ranges(&self) -> Ref<RangeMap<u64, (u16, String)>> {
        self.ranges.borrow()
    }

    /// Mutable ranges
    pub fn ranges_mut(&mut self) -> RefMut<RangeMap<u64, (u16, String)>> {
        (*self.ranges).borrow_mut()
    }
}
