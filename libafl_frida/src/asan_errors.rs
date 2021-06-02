use backtrace::Backtrace;
use capstone::{arch::BuildsCapstone, Capstone};
use color_backtrace::{default_output_stream, BacktracePrinter, Verbosity};
#[cfg(target_arch = "aarch64")]
use frida_gum::interceptor::Interceptor;

#[cfg(any(target_os = "linux", target_os = "android"))]
use libafl::bolts::os::find_mapping_for_address;

use libafl::{
    bolts::{ownedref::OwnedPtr, tuples::Named},
    corpus::Testcase,
    events::EventFirer,
    executors::{ExitKind, HasExecHooks},
    feedbacks::Feedback,
    inputs::{HasTargetBytes, Input},
    observers::{Observer, ObserversTuple},
    state::HasMetadata,
    Error, SerdeAny,
};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};
use std::io::Write;
use termcolor::{Color, ColorSpec, WriteColor};

use crate::{alloc::AllocationMetadata, FridaOptions};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AsanReadWriteError {
    pub registers: [usize; 32],
    pub pc: usize,
    pub fault: (u16, u16, usize, usize),
    pub metadata: AllocationMetadata,
    pub backtrace: Backtrace,
}

#[derive(Debug, Clone, Serialize, Deserialize, SerdeAny)]
pub(crate) enum AsanError {
    OobRead(AsanReadWriteError),
    OobWrite(AsanReadWriteError),
    ReadAfterFree(AsanReadWriteError),
    WriteAfterFree(AsanReadWriteError),
    DoubleFree((usize, AllocationMetadata, Backtrace)),
    UnallocatedFree((usize, Backtrace)),
    Unknown(([usize; 32], usize, (u16, u16, usize, usize), Backtrace)),
    Leak((usize, AllocationMetadata)),
    StackOobRead(([usize; 32], usize, (u16, u16, usize, usize), Backtrace)),
    StackOobWrite(([usize; 32], usize, (u16, u16, usize, usize), Backtrace)),
    BadFuncArgRead((String, usize, usize, usize, Backtrace)),
    BadFuncArgWrite((String, usize, usize, usize, Backtrace)),
}

impl AsanError {
    fn description(&self) -> &str {
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
#[allow(clippy::unsafe_derive_deserialize)]
#[derive(Debug, Clone, Serialize, Deserialize, SerdeAny)]
pub struct AsanErrors {
    options: FridaOptions,
    errors: Vec<AsanError>,
}

impl AsanErrors {
    /// Creates a new `AsanErrors` struct
    #[must_use]
    pub fn new(options: FridaOptions) -> Self {
        Self {
            options,
            errors: Vec::new(),
        }
    }

    /// Clears this `AsanErrors` struct
    pub fn clear(&mut self) {
        self.errors.clear()
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

    /// Get a mutable reference to the global [`AsanErrors`] object
    pub fn get_mut<'a>() -> &'a mut Self {
        unsafe { ASAN_ERRORS.as_mut().unwrap() }
    }

    /// Report an error
    #[allow(clippy::too_many_lines)]
    pub(crate) fn report_error(
        &mut self,
        error: AsanError,
        instrumented_ranges: Option<&RangeMap<usize, String>>,
    ) {
        self.errors.push(error.clone());

        let mut out_stream = default_output_stream();
        let output = out_stream.as_mut();

        let backtrace_printer = BacktracePrinter::new()
            .clear_frame_filters()
            .print_addresses(true)
            .verbosity(Verbosity::Full)
            .add_frame_filter(Box::new(|frames| {
                frames.retain(
                    |x| matches!(&x.name, Some(n) if !n.starts_with("libafl_frida::asan_rt::")),
                )
            }));

        #[allow(clippy::non_ascii_literal)]
        writeln!(output, "{:━^100}", " Memory error detected! ").unwrap();
        output
            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
            .unwrap();
        write!(output, "{}", error.description()).unwrap();
        match error {
            AsanError::OobRead(mut error)
            | AsanError::OobWrite(mut error)
            | AsanError::ReadAfterFree(mut error)
            | AsanError::WriteAfterFree(mut error) => {
                let (basereg, indexreg, _displacement, fault_address) = error.fault;

                if let Some((range, path)) = instrumented_ranges.unwrap().get_key_value(&error.pc) {
                    writeln!(
                        output,
                        " at 0x{:x} ({}@0x{:04x}), faulting address 0x{:x}",
                        error.pc,
                        path,
                        error.pc - range.start,
                        fault_address
                    )
                    .unwrap();
                } else {
                    writeln!(
                        output,
                        " at 0x{:x}, faulting address 0x{:x}",
                        error.pc, fault_address
                    )
                    .unwrap();
                }
                output.reset().unwrap();

                #[allow(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " REGISTERS ").unwrap();
                for reg in 0..=30 {
                    if reg == basereg {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                            .unwrap();
                    } else if reg == indexreg {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))
                            .unwrap();
                    }
                    write!(
                        output,
                        "x{:02}: 0x{:016x} ",
                        reg, error.registers[reg as usize]
                    )
                    .unwrap();
                    output.reset().unwrap();
                    if reg % 4 == 3 {
                        writeln!(output).unwrap();
                    }
                }
                writeln!(output, "pc : 0x{:016x} ", error.pc).unwrap();

                #[allow(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " CODE ").unwrap();
                let mut cs = Capstone::new()
                    .arm64()
                    .mode(capstone::arch::arm64::ArchMode::Arm)
                    .build()
                    .unwrap();
                cs.set_skipdata(true).expect("failed to set skipdata");

                let start_pc = error.pc - 4 * 5;
                for insn in cs
                    .disasm_count(
                        unsafe { std::slice::from_raw_parts(start_pc as *mut u8, 4 * 11) },
                        start_pc as u64,
                        11,
                    )
                    .expect("failed to disassemble instructions")
                    .iter()
                {
                    if insn.address() as usize == error.pc {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                            .unwrap();
                        writeln!(output, "\t => {}", insn).unwrap();
                        output.reset().unwrap();
                    } else {
                        writeln!(output, "\t    {}", insn).unwrap();
                    }
                }
                backtrace_printer
                    .print_trace(&error.backtrace, output)
                    .unwrap();

                #[allow(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " ALLOCATION INFO ").unwrap();
                let offset: i64 = fault_address as i64 - error.metadata.address as i64;
                let direction = if offset > 0 { "right" } else { "left" };
                writeln!(
                    output,
                    "access is {} to the {} of the 0x{:x} byte allocation at 0x{:x}",
                    offset, direction, error.metadata.size, error.metadata.address
                )
                .unwrap();

                if error.metadata.is_malloc_zero {
                    writeln!(output, "allocation was zero-sized").unwrap();
                }

                if let Some(backtrace) = error.metadata.allocation_site_backtrace.as_mut() {
                    writeln!(output, "allocation site backtrace:").unwrap();
                    backtrace.resolve();
                    backtrace_printer.print_trace(backtrace, output).unwrap();
                }

                if error.metadata.freed {
                    #[allow(clippy::non_ascii_literal)]
                    writeln!(output, "{:━^100}", " FREE INFO ").unwrap();
                    if let Some(backtrace) = error.metadata.release_site_backtrace.as_mut() {
                        writeln!(output, "free site backtrace:").unwrap();
                        backtrace.resolve();
                        backtrace_printer.print_trace(backtrace, output).unwrap();
                    }
                }
            }
            AsanError::BadFuncArgRead((name, pc, address, size, backtrace))
            | AsanError::BadFuncArgWrite((name, pc, address, size, backtrace)) => {
                writeln!(
                    output,
                    " in call to {}, argument {:#016x}, size: {:#x}",
                    name, address, size
                )
                .unwrap();
                output.reset().unwrap();

                #[cfg(target_arch = "aarch64")]
                {
                    let invocation = Interceptor::current_invocation();
                    let cpu_context = invocation.cpu_context();
                    if let Some((range, path)) = instrumented_ranges.unwrap().get_key_value(&pc) {
                        writeln!(
                            output,
                            " at 0x{:x} ({}@0x{:04x})",
                            pc,
                            path,
                            pc - range.start,
                        )
                        .unwrap();
                    } else {
                        writeln!(output, " at 0x{:x}", pc,).unwrap();
                    }

                    #[allow(clippy::non_ascii_literal)]
                    writeln!(output, "{:━^100}", " REGISTERS ").unwrap();
                    for reg in 0..29 {
                        let val = cpu_context.reg(reg);
                        if val as usize == address {
                            output
                                .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                                .unwrap();
                        }
                        write!(output, "x{:02}: 0x{:016x} ", reg, val).unwrap();
                        output.reset().unwrap();
                        if reg % 4 == 3 {
                            writeln!(output).unwrap();
                        }
                    }
                    write!(output, "sp : 0x{:016x} ", cpu_context.sp()).unwrap();
                    write!(output, "lr : 0x{:016x} ", cpu_context.lr()).unwrap();
                    writeln!(output, "pc : 0x{:016x} ", cpu_context.pc()).unwrap();
                }

                backtrace_printer.print_trace(&backtrace, output).unwrap();
            }
            AsanError::DoubleFree((ptr, mut metadata, backtrace)) => {
                writeln!(output, " of {:?}", ptr).unwrap();
                output.reset().unwrap();
                backtrace_printer.print_trace(&backtrace, output).unwrap();

                #[allow(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " ALLOCATION INFO ").unwrap();
                writeln!(
                    output,
                    "allocation at 0x{:x}, with size 0x{:x}",
                    metadata.address, metadata.size
                )
                .unwrap();
                if metadata.is_malloc_zero {
                    writeln!(output, "allocation was zero-sized").unwrap();
                }

                if let Some(backtrace) = metadata.allocation_site_backtrace.as_mut() {
                    writeln!(output, "allocation site backtrace:").unwrap();
                    backtrace.resolve();
                    backtrace_printer.print_trace(backtrace, output).unwrap();
                }
                #[allow(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " FREE INFO ").unwrap();
                if let Some(backtrace) = metadata.release_site_backtrace.as_mut() {
                    writeln!(output, "previous free site backtrace:").unwrap();
                    backtrace.resolve();
                    backtrace_printer.print_trace(backtrace, output).unwrap();
                }
            }
            AsanError::UnallocatedFree((ptr, backtrace)) => {
                writeln!(output, " of {:#016x}", ptr).unwrap();
                output.reset().unwrap();
                backtrace_printer.print_trace(&backtrace, output).unwrap();
            }
            AsanError::Leak((ptr, mut metadata)) => {
                writeln!(output, " of {:#016x}", ptr).unwrap();
                output.reset().unwrap();

                #[allow(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " ALLOCATION INFO ").unwrap();
                writeln!(
                    output,
                    "allocation at 0x{:x}, with size 0x{:x}",
                    metadata.address, metadata.size
                )
                .unwrap();
                if metadata.is_malloc_zero {
                    writeln!(output, "allocation was zero-sized").unwrap();
                }

                if let Some(backtrace) = metadata.allocation_site_backtrace.as_mut() {
                    writeln!(output, "allocation site backtrace:").unwrap();
                    backtrace.resolve();
                    backtrace_printer.print_trace(backtrace, output).unwrap();
                }
            }
            AsanError::Unknown((registers, pc, fault, backtrace))
            | AsanError::StackOobRead((registers, pc, fault, backtrace))
            | AsanError::StackOobWrite((registers, pc, fault, backtrace)) => {
                let (basereg, indexreg, _displacement, fault_address) = fault;

                if let Ok((start, _, _, path)) = find_mapping_for_address(pc) {
                    writeln!(
                        output,
                        " at 0x{:x} ({}:0x{:04x}), faulting address 0x{:x}",
                        pc,
                        path,
                        pc - start,
                        fault_address
                    )
                    .unwrap();
                } else {
                    writeln!(
                        output,
                        " at 0x{:x}, faulting address 0x{:x}",
                        pc, fault_address
                    )
                    .unwrap();
                }
                output.reset().unwrap();

                #[allow(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " REGISTERS ").unwrap();
                for reg in 0..=30 {
                    if reg == basereg {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                            .unwrap();
                    } else if reg == indexreg {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Yellow)))
                            .unwrap();
                    }
                    write!(output, "x{:02}: 0x{:016x} ", reg, registers[reg as usize]).unwrap();
                    output.reset().unwrap();
                    if reg % 4 == 3 {
                        writeln!(output).unwrap();
                    }
                }
                writeln!(output, "pc : 0x{:016x} ", pc).unwrap();

                #[allow(clippy::non_ascii_literal)]
                writeln!(output, "{:━^100}", " CODE ").unwrap();
                let mut cs = Capstone::new()
                    .arm64()
                    .mode(capstone::arch::arm64::ArchMode::Arm)
                    .build()
                    .unwrap();
                cs.set_skipdata(true).expect("failed to set skipdata");

                let start_pc = pc - 4 * 5;
                for insn in cs
                    .disasm_count(
                        unsafe { std::slice::from_raw_parts(start_pc as *mut u8, 4 * 11) },
                        start_pc as u64,
                        11,
                    )
                    .expect("failed to disassemble instructions")
                    .iter()
                {
                    if insn.address() as usize == pc {
                        output
                            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))
                            .unwrap();
                        writeln!(output, "\t => {}", insn).unwrap();
                        output.reset().unwrap();
                    } else {
                        writeln!(output, "\t    {}", insn).unwrap();
                    }
                }
                backtrace_printer.print_trace(&backtrace, output).unwrap();
            }
        };

        if !self.options.asan_continue_after_error() {
            panic!("Crashing target!");
        }
    }
}

/// static field for `AsanErrors` for a run
pub static mut ASAN_ERRORS: Option<AsanErrors> = None;

/// An observer for frida address sanitizer `AsanError`s for a frida executor run
#[derive(Serialize, Deserialize)]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct AsanErrorsObserver {
    errors: OwnedPtr<Option<AsanErrors>>,
}

impl Observer for AsanErrorsObserver {}

impl<EM, I, S, Z> HasExecHooks<EM, I, S, Z> for AsanErrorsObserver {
    fn pre_exec(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        unsafe {
            if ASAN_ERRORS.is_some() {
                ASAN_ERRORS.as_mut().unwrap().clear();
            }
        }

        Ok(())
    }
}

impl Named for AsanErrorsObserver {
    #[inline]
    fn name(&self) -> &str {
        "AsanErrors"
    }
}

impl AsanErrorsObserver {
    /// Creates a new `AsanErrorsObserver`, pointing to a constant `AsanErrors` field
    #[must_use]
    pub fn new(errors: &'static Option<AsanErrors>) -> Self {
        Self {
            errors: OwnedPtr::Ptr(errors as *const Option<AsanErrors>),
        }
    }

    /// Creates a new `AsanErrorsObserver`, owning the `AsanErrors`
    #[must_use]
    pub fn new_owned(errors: Option<AsanErrors>) -> Self {
        Self {
            errors: OwnedPtr::Owned(Box::new(errors)),
        }
    }

    /// Creates a new `AsanErrorsObserver` from a raw ptr
    #[must_use]
    pub fn new_from_ptr(errors: *const Option<AsanErrors>) -> Self {
        Self {
            errors: OwnedPtr::Ptr(errors),
        }
    }

    /// gets the [`AsanErrors`] from the previous run
    #[must_use]
    pub fn errors(&self) -> Option<&AsanErrors> {
        match &self.errors {
            OwnedPtr::Ptr(p) => unsafe { p.as_ref().unwrap().as_ref() },
            OwnedPtr::Owned(b) => b.as_ref().as_ref(),
        }
    }
}

/// A feedback reporting potential [`AsanErrors`] from an `AsanErrorsObserver`
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AsanErrorsFeedback {
    errors: Option<AsanErrors>,
}

impl<I, S> Feedback<I, S> for AsanErrorsFeedback
where
    I: Input + HasTargetBytes,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<I, S>,
        OT: ObserversTuple,
    {
        let observer = observers
            .match_name::<AsanErrorsObserver>("AsanErrors")
            .expect("An AsanErrorsFeedback needs an AsanErrorsObserver");
        match observer.errors() {
            None => Ok(false),
            Some(errors) => {
                if errors.errors.is_empty() {
                    Ok(false)
                } else {
                    self.errors = Some(errors.clone());
                    Ok(true)
                }
            }
        }
    }

    fn append_metadata(&mut self, _state: &mut S, testcase: &mut Testcase<I>) -> Result<(), Error> {
        if let Some(errors) = &self.errors {
            testcase.add_metadata(errors.clone());
        }

        Ok(())
    }

    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.errors = None;
        Ok(())
    }
}

impl Named for AsanErrorsFeedback {
    #[inline]
    fn name(&self) -> &str {
        "AsanErrors"
    }
}

impl AsanErrorsFeedback {
    /// Create a new `AsanErrorsFeedback`
    #[must_use]
    pub fn new() -> Self {
        Self { errors: None }
    }
}

impl Default for AsanErrorsFeedback {
    fn default() -> Self {
        Self::new()
    }
}
