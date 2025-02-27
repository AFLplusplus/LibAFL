//! Errors that can be caught by the `libafl_frida` address sanitizer.
use alloc::borrow::Cow;
use core::{fmt::Debug, marker::PhantomData};
use std::{
    io::Write,
    sync::{Mutex, MutexGuard},
};

use backtrace::Backtrace;
use color_backtrace::{BacktracePrinter, Verbosity, default_output_stream};
#[cfg(target_arch = "aarch64")]
use frida_gum::interceptor::Interceptor;
use frida_gum::{Gum, Process};
use libafl::{
    Error, HasMetadata,
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    observers::Observer,
};
use libafl_bolts::{
    Named, SerdeAny,
    ownedref::OwnedPtr,
    tuples::{Handle, Handled, MatchNameRef},
};
use mmap_rs::MmapOptions;
use serde::{Deserialize, Serialize};
use termcolor::{Color, ColorSpec, WriteColor};
#[cfg(target_arch = "aarch64")]
use yaxpeax_arch::Arch;
use yaxpeax_arch::LengthedInstruction;
#[cfg(target_arch = "aarch64")]
use yaxpeax_arm::armv8::a64::ARMv8;
#[cfg(target_arch = "x86_64")]
use yaxpeax_x86::amd64::InstDecoder;

#[cfg(target_arch = "x86_64")]
use crate::asan::asan_rt::ASAN_SAVE_REGISTER_NAMES;
use crate::{
    allocator::AllocationMetadata, asan::asan_rt::ASAN_SAVE_REGISTER_COUNT, utils::disas_count,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AsanReadWriteError {
    pub registers: [usize; ASAN_SAVE_REGISTER_COUNT],
    pub pc: usize,
    pub fault: (Option<u16>, Option<u16>, usize, usize),
    pub metadata: AllocationMetadata,
    pub backtrace: Backtrace,
}

#[expect(clippy::type_complexity)]
#[derive(Debug, Clone, Serialize, Deserialize, SerdeAny)]
pub(crate) enum AsanError {
    OobRead(AsanReadWriteError),
    OobWrite(AsanReadWriteError),
    ReadAfterFree(AsanReadWriteError),
    WriteAfterFree(AsanReadWriteError),
    DoubleFree((usize, AllocationMetadata, Backtrace)),
    UnallocatedFree((usize, Backtrace)),
    Unknown(
        (
            [usize; ASAN_SAVE_REGISTER_COUNT],
            usize,
            (Option<u16>, Option<u16>, usize, usize),
            Backtrace,
        ),
    ),
    Leak((usize, AllocationMetadata)),
    StackOobRead(
        (
            [usize; ASAN_SAVE_REGISTER_COUNT],
            usize,
            (Option<u16>, Option<u16>, usize, usize),
            Backtrace,
        ),
    ),
    StackOobWrite(
        (
            [usize; ASAN_SAVE_REGISTER_COUNT],
            usize,
            (Option<u16>, Option<u16>, usize, usize),
            Backtrace,
        ),
    ),
    BadFuncArgRead((String, usize, usize, usize, Backtrace)),
    BadFuncArgWrite((String, usize, usize, usize, Backtrace)),
}

impl AsanError {
    pub fn description(&self) -> &str {
        match self {
            AsanError::OobRead(_) => "heap out-of-bounds read",
            AsanError::OobWrite(_) => "heap out-of-bounds write",
            AsanError::DoubleFree(_) => "double-free",
            AsanError::UnallocatedFree(_) => "unallocated-free",
            AsanError::WriteAfterFree(_) => "heap use-after-free write",
            AsanError::ReadAfterFree(_) => "heap use-after-free read",
            AsanError::Unknown(_) => "heap unknown",
            AsanError::Leak(_) => "memory-leak",
            AsanError::StackOobRead(_) => "stack out-of-bounds read",
            AsanError::StackOobWrite(_) => "stack out-of-bounds write",
            AsanError::BadFuncArgRead(_) => "function arg resulting in bad read",
            AsanError::BadFuncArgWrite(_) => "function arg resulting in bad write",
        }
    }
}

/// A struct holding errors that occurred during frida address sanitizer runs
#[expect(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize, SerdeAny)]
pub struct AsanErrors {
    continue_on_error: bool,
    pub(crate) errors: Vec<AsanError>,
}

impl AsanErrors {
    /// Creates a new `AsanErrors` struct
    #[must_use]
    pub const fn new(continue_on_error: bool) -> Self {
        Self {
            errors: Vec::new(),
            continue_on_error,
        }
    }

    /// Clears this `AsanErrors` struct
    pub fn clear(&mut self) {
        self.errors.clear();
    }

    /// Gets the amount of `AsanErrors` in this struct
    #[must_use]
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Returns `true` if no errors occurred
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Get a mutable reference to the global [`struct@AsanErrors`] object
    pub fn get_mut_blocking() -> MutexGuard<'static, Self> {
        ASAN_ERRORS.lock().unwrap()
    }

    /// Sets if this [`AsanErrors`] variable should continue on error, or not.
    pub fn set_continue_on_error(&mut self, continue_on_error: bool) {
        self.continue_on_error = continue_on_error;
    }

    /// Report an error, returns true if the caller should panic
    #[expect(clippy::too_many_lines)]
    pub(crate) fn report_error(&mut self, error: AsanError) -> bool {
        let mut out_stream = default_output_stream();
        let output = out_stream.as_mut();

        let backtrace_printer = BacktracePrinter::new()
            .clear_frame_filters()
            .print_addresses(true)
            .verbosity(Verbosity::Full)
            .add_frame_filter(Box::new(|frames| {
                frames.retain(
                    |x| matches!(&x.name, Some(n) if !n.starts_with("libafl_frida::asan_rt::")),
                );
            }));

        #[expect(clippy::non_ascii_literal)]
        writeln!(output, "{:━^100}", " Memory error detected! ").unwrap();
        output
            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
            .unwrap();
        write!(output, "{}", error.description()).unwrap();
        match &error {
            AsanError::OobRead(error)
            | AsanError::OobWrite(error)
            | AsanError::ReadAfterFree(error)
            | AsanError::WriteAfterFree(error) => {
                let (basereg, indexreg, _displacement, fault_address) = error.fault;

                if let Some(module_details) =
                    Process::obtain(&Gum::obtain()).find_module_by_address(error.pc)
                {
                    writeln!(
                        output,
                        " at 0x{:x} ({}@0x{:04x}), faulting address 0x{:x}",
                        error.pc,
                        module_details.path(),
                        error.pc - module_details.range().base_address().0 as usize,
                        fault_address
                    )
                    .unwrap();
                } else {
                    writeln!(
                        output,
                        " at 0x{:x}, faulting address 0x{fault_address:x}",
                        error.pc
                    )
                    .unwrap();
                }
                output.reset().unwrap();

                #[expect(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " REGISTERS ").unwrap();
                #[cfg(target_arch = "aarch64")]
                for reg in 0..=30 {
                    if basereg.is_some() && reg == basereg.unwrap() as usize {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                            .unwrap();
                    } else if indexreg.is_some() && reg == indexreg.unwrap() as usize {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))
                            .unwrap();
                    }
                    write!(output, "x{reg:02}: 0x{:016x} ", error.registers[reg]).unwrap();
                    output.reset().unwrap();
                    if reg % 4 == 3 {
                        writeln!(output).unwrap();
                    }
                }
                #[cfg(target_arch = "aarch64")]
                writeln!(output, "pc : 0x{:016x} ", error.pc).unwrap();

                #[cfg(target_arch = "x86_64")]
                for (reg, name) in ASAN_SAVE_REGISTER_NAMES
                    .iter()
                    .enumerate()
                    .take(ASAN_SAVE_REGISTER_COUNT)
                {
                    if basereg.is_some() && reg == basereg.unwrap() as usize {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                            .unwrap();
                    } else if indexreg.is_some() && reg == indexreg.unwrap() as usize {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))
                            .unwrap();
                    }
                    write!(output, "{name}: 0x{:016x} ", error.registers[reg]).unwrap();
                    output.reset().unwrap();
                    if reg % 4 == 3 {
                        writeln!(output).unwrap();
                    }
                }

                #[cfg(target_arch = "x86_64")]
                writeln!(output, "rip: 0x{:016x}", error.pc).unwrap();

                #[expect(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " CODE ").unwrap();

                #[cfg(target_arch = "aarch64")]
                let decoder = <ARMv8 as Arch>::Decoder::default();

                #[cfg(target_arch = "x86_64")]
                let decoder = InstDecoder::minimal();

                let start_pc = error.pc - 4 * 5;
                #[cfg(target_arch = "x86_64")]
                let insts = disas_count(
                    &decoder,
                    unsafe { core::slice::from_raw_parts(start_pc as *mut u8, 15 * 11) },
                    11,
                );

                #[cfg(target_arch = "aarch64")]
                let insts = disas_count(
                    &decoder,
                    unsafe { std::slice::from_raw_parts(start_pc as *mut u8, 4 * 11) },
                    11,
                );

                let mut inst_address = start_pc;

                for insn in insts {
                    if inst_address == error.pc {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                            .unwrap();
                        writeln!(output, "\t => {insn}").unwrap();
                        output.reset().unwrap();
                    } else {
                        writeln!(output, "\t    {insn}").unwrap();
                    }

                    inst_address += insn.len().to_const() as usize;
                }
                backtrace_printer
                    .print_trace(&error.backtrace, output)
                    .unwrap();

                #[expect(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " ALLOCATION INFO ").unwrap();
                let fault_address: i64 = fault_address.try_into().unwrap();
                let metadata_address: i64 = error.metadata.address.try_into().unwrap();
                #[allow(clippy::cast_possible_wrap)]
                let offset: i64 =
                    fault_address - (metadata_address + MmapOptions::page_size() as i64);
                let direction = if offset > 0 { "right" } else { "left" };
                writeln!(
                    output,
                    "access is {:#x} to the {} of the {:#x} byte allocation at {:#x}",
                    offset,
                    direction,
                    error.metadata.size,
                    error.metadata.address + MmapOptions::page_size()
                )
                .unwrap();

                if error.metadata.is_malloc_zero {
                    writeln!(output, "allocation was zero-sized").unwrap();
                }

                let mut allocation_site_backtrace =
                    error.metadata.allocation_site_backtrace.clone();
                let mut release_site_backtrace = error.metadata.release_site_backtrace.clone();

                if let Some(backtrace) = &mut allocation_site_backtrace {
                    writeln!(output, "allocation site backtrace:").unwrap();
                    backtrace.resolve();
                    backtrace_printer.print_trace(backtrace, output).unwrap();
                }

                if error.metadata.freed {
                    #[expect(clippy::non_ascii_literal)]
                    writeln!(output, "{:━^100}", " FREE INFO ").unwrap();
                    if let Some(backtrace) = &mut release_site_backtrace {
                        writeln!(output, "free site backtrace:").unwrap();
                        backtrace.resolve();
                        backtrace_printer.print_trace(backtrace, output).unwrap();
                    }
                }
            }
            AsanError::BadFuncArgRead((name, _pc, address, size, backtrace))
            | AsanError::BadFuncArgWrite((name, _pc, address, size, backtrace)) => {
                writeln!(
                    output,
                    " in call to {name}, argument {address:#016x}, size: {size:#x}"
                )
                .unwrap();
                output.reset().unwrap();

                #[cfg(target_arch = "aarch64")]
                {
                    let invocation = Interceptor::current_invocation();
                    let cpu_context = invocation.cpu_context();
                    if let Some(module_details) =
                        Process::obtain(&Gum::obtain()).find_module_by_address(*_pc)
                    {
                        writeln!(
                            output,
                            " at 0x{:x} ({}@0x{:04x})",
                            _pc,
                            module_details.path(),
                            _pc - module_details.range().base_address().0 as usize,
                        )
                        .unwrap();
                    } else {
                        writeln!(output, " at 0x{_pc:x}").unwrap();
                    }

                    #[expect(clippy::non_ascii_literal)]
                    writeln!(output, "{:━^100}", " REGISTERS ").unwrap();
                    for reg in 0..29 {
                        let val = cpu_context.reg(reg);
                        if val as usize == *address {
                            output
                                .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                                .unwrap();
                        }
                        write!(output, "x{reg:02}: 0x{val:016x} ").unwrap();
                        output.reset().unwrap();
                        if reg % 4 == 3 {
                            writeln!(output).unwrap();
                        }
                    }
                    write!(output, "sp : 0x{:016x} ", cpu_context.sp()).unwrap();
                    write!(output, "lr : 0x{:016x} ", cpu_context.lr()).unwrap();
                    writeln!(output, "pc : 0x{:016x} ", cpu_context.pc()).unwrap();
                }

                backtrace_printer.print_trace(backtrace, output).unwrap();
            }
            AsanError::DoubleFree((ptr, metadata, backtrace)) => {
                writeln!(output, " of {ptr:?}").unwrap();
                output.reset().unwrap();
                backtrace_printer.print_trace(backtrace, output).unwrap();

                #[expect(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " ALLOCATION INFO ").unwrap();
                writeln!(
                    output,
                    "allocation at 0x{:x}, with size 0x{:x}",
                    metadata.address + MmapOptions::page_size(),
                    metadata.size
                )
                .unwrap();
                if metadata.is_malloc_zero {
                    writeln!(output, "allocation was zero-sized").unwrap();
                }

                let mut allocation_site_backtrace = metadata.allocation_site_backtrace.clone();
                let mut release_site_backtrace = metadata.release_site_backtrace.clone();

                if let Some(backtrace) = &mut allocation_site_backtrace {
                    writeln!(output, "allocation site backtrace:").unwrap();
                    backtrace.resolve();
                    backtrace_printer.print_trace(backtrace, output).unwrap();
                }
                #[expect(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " FREE INFO ").unwrap();
                if let Some(backtrace) = &mut release_site_backtrace {
                    writeln!(output, "previous free site backtrace:").unwrap();
                    backtrace.resolve();
                    backtrace_printer.print_trace(backtrace, output).unwrap();
                }
            }
            AsanError::UnallocatedFree((ptr, backtrace)) => {
                writeln!(output, " of {ptr:#016x}").unwrap();
                output.reset().unwrap();
                backtrace_printer.print_trace(backtrace, output).unwrap();
            }
            AsanError::Leak((ptr, metadata)) => {
                writeln!(output, " of {ptr:#016x}").unwrap();
                output.reset().unwrap();

                #[expect(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " ALLOCATION INFO ").unwrap();
                writeln!(
                    output,
                    "allocation at 0x{:x}, with size 0x{:x}",
                    metadata.address + MmapOptions::page_size(),
                    metadata.size
                )
                .unwrap();
                if metadata.is_malloc_zero {
                    writeln!(output, "allocation was zero-sized").unwrap();
                }

                let mut allocation_site_backtrace = metadata.allocation_site_backtrace.clone();

                if let Some(backtrace) = &mut allocation_site_backtrace {
                    writeln!(output, "allocation site backtrace:").unwrap();
                    backtrace.resolve();
                    backtrace_printer.print_trace(backtrace, output).unwrap();
                }
            }
            AsanError::Unknown((registers, pc, fault, backtrace))
            | AsanError::StackOobRead((registers, pc, fault, backtrace))
            | AsanError::StackOobWrite((registers, pc, fault, backtrace)) => {
                let (basereg, indexreg, _displacement, fault_address) = fault;

                if let Some(module_details) =
                    Process::obtain(&Gum::obtain()).find_module_by_address(*pc)
                {
                    writeln!(
                        output,
                        " at 0x{:x} ({}:0x{:04x}), faulting address 0x{:x}",
                        pc,
                        module_details.path(),
                        pc - module_details.range().base_address().0 as usize,
                        fault_address
                    )
                    .unwrap();
                } else {
                    writeln!(output, " at 0x{pc:x}, faulting address 0x{fault_address:x}").unwrap();
                }
                output.reset().unwrap();

                #[expect(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " REGISTERS ").unwrap();

                #[cfg(target_arch = "aarch64")]
                for (reg, val) in registers.iter().enumerate().take(30 + 1) {
                    if basereg.is_some() && reg == basereg.unwrap() as usize {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                            .unwrap();
                    } else if indexreg.is_some() && reg == indexreg.unwrap() as usize {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))
                            .unwrap();
                    }
                    write!(output, "x{reg:02}: 0x{val:016x} ").unwrap();
                    output.reset().unwrap();
                    if reg % 4 == 3 {
                        writeln!(output).unwrap();
                    }
                }
                #[cfg(target_arch = "aarch64")]
                writeln!(output, "pc : 0x{pc:016x} ").unwrap();

                #[cfg(target_arch = "x86_64")]
                for reg in 0..ASAN_SAVE_REGISTER_COUNT {
                    if basereg.is_some() && reg == basereg.unwrap() as usize {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                            .unwrap();
                    } else if indexreg.is_some() && reg == indexreg.unwrap() as usize {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))
                            .unwrap();
                    }
                    write!(
                        output,
                        "{}: 0x{:016x} ",
                        ASAN_SAVE_REGISTER_NAMES[reg], registers[reg]
                    )
                    .unwrap();
                    output.reset().unwrap();
                    if reg % 4 == 3 {
                        writeln!(output).unwrap();
                    }
                }

                #[cfg(target_arch = "x86_64")]
                writeln!(output, "Rip: 0x{pc:016x}").unwrap();

                #[expect(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " CODE ").unwrap();

                #[cfg(target_arch = "aarch64")]
                let decoder = <ARMv8 as Arch>::Decoder::default();

                #[cfg(target_arch = "x86_64")]
                let decoder = InstDecoder::minimal();

                let start_pc = pc;

                #[cfg(target_arch = "x86_64")]
                let insts = disas_count(
                    &decoder,
                    unsafe { core::slice::from_raw_parts(*start_pc as *mut u8, 15 * 11) },
                    11,
                );

                #[cfg(target_arch = "aarch64")]
                let insts = disas_count(
                    &decoder,
                    unsafe { std::slice::from_raw_parts(*start_pc as *mut u8, 4 * 11) },
                    11,
                );

                let mut inst_address = *start_pc;
                for insn in insts {
                    if inst_address == *pc {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                            .unwrap();
                        writeln!(output, "\t => {insn}").unwrap();
                        output.reset().unwrap();
                    } else {
                        writeln!(output, "\t    {insn}").unwrap();
                    }

                    inst_address += insn.len().to_const() as usize;
                }
                backtrace_printer.print_trace(backtrace, output).unwrap();
            }
        }

        self.errors.push(error);

        !self.continue_on_error
    }
}

/// static field for `AsanErrors` for a run
pub static ASAN_ERRORS: Mutex<AsanErrors> = Mutex::new(AsanErrors::new(true));

/// An observer for frida address sanitizer `AsanError`s for a `Frida` executor run
#[derive(Debug, Serialize, Deserialize)]
#[expect(clippy::unsafe_derive_deserialize)]
pub enum AsanErrorsObserver {
    /// Observer referencing a list behind a [`OwnedPtr`] pointer.
    Ptr(OwnedPtr<AsanErrors>),
    /// Observer referencing the static [`ASAN_ERRORS`] variable.
    Static,
}

impl<I, S> Observer<I, S> for AsanErrorsObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        AsanErrors::get_mut_blocking().clear();

        Ok(())
    }
}

impl Named for AsanErrorsObserver {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static ASAN_ERRORS_NAME: Cow<'static, str> = Cow::Borrowed("AsanErrors");
        &ASAN_ERRORS_NAME
    }
}

impl AsanErrorsObserver {
    /// Creates a new [`AsanErrorsObserver`], pointing to a constant `AsanErrors` field
    #[must_use]
    pub fn new(errors: OwnedPtr<AsanErrors>) -> Self {
        Self::Ptr(errors)
    }

    /// Creates a new [`AsanErrorsObserver`], pointing to the [`ASAN_ERRORS`] global static field.
    ///
    /// # Safety
    /// The field should not be accessed multiple times at the same time (i.e., from different threads)!
    #[must_use]
    pub fn from_static_asan_errors() -> Self {
        Self::Static
    }

    /// Creates a new `AsanErrorsObserver`, owning the `AsanErrors`
    #[must_use]
    pub fn owned(errors: AsanErrors) -> Self {
        Self::Ptr(OwnedPtr::Owned(Box::new(errors)))
    }

    /// Creates a new `AsanErrorsObserver` from a raw ptr
    ///
    /// # Safety
    /// Will dereference this pointer at a later point in time.
    /// The pointer *must* outlive this [`AsanErrorsObserver`]'s lifetime.
    #[must_use]
    pub unsafe fn from_ptr(errors: *const AsanErrors) -> Self {
        Self::Ptr(OwnedPtr::Ptr(errors))
    }

    /// Gets the [`struct@AsanErrors`] from the previous run
    #[must_use]
    pub fn errors(&self) -> AsanErrors {
        match self {
            Self::Ptr(errors) => match errors {
                OwnedPtr::Ptr(p) => unsafe { p.as_ref().unwrap().clone() },
                OwnedPtr::Owned(b) => b.as_ref().clone(),
            },
            Self::Static => AsanErrors::get_mut_blocking().clone(),
        }
    }
}

/// A feedback reporting potential [`struct@AsanErrors`] from an `AsanErrorsObserver`
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsanErrorsFeedback<S> {
    errors: Option<AsanErrors>,
    observer_handle: Handle<AsanErrorsObserver>,
    phantom: PhantomData<S>,
}

impl<S> StateInitializer<S> for AsanErrorsFeedback<S> {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for AsanErrorsFeedback<S>
where
    S: Debug,
    OT: MatchNameRef,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let observer = observers
            .get(&self.observer_handle)
            .expect("An AsanErrorsFeedback needs an AsanErrorsObserver");
        let errors = observer.errors();
        if errors.is_empty() {
            Ok(false)
        } else {
            self.errors = Some(errors);
            Ok(true)
        }
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        if let Some(errors) = &self.errors {
            testcase.add_metadata(errors.clone());
        }

        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.errors = None;
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(self.errors.is_some())
    }
}

impl<S> Named for AsanErrorsFeedback<S> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl<S> AsanErrorsFeedback<S> {
    /// Create a new `AsanErrorsFeedback`
    #[must_use]
    pub fn new(obs: &AsanErrorsObserver) -> Self {
        Self {
            errors: None,
            observer_handle: obs.handle(),
            phantom: PhantomData,
        }
    }
}
