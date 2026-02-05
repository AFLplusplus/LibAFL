use core::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
    ptr,
    time::Duration,
};
use std::collections::HashSet;

use libafl::{
    Error,
    executors::{Executor, ExitKind, HasObservers},
    inputs::HasTargetBytes,
    state::HasExecutions,
};
use libafl_bolts::{
    AsSlice, AsSliceMut,
    fs::{INPUTFILE_STD, InputFile},
    shmem::{NopShMem, NopShMemProvider, ShMem, ShMemProvider},
    tuples::RefIndexable,
};
use tinyinst::tinyinst::{TinyInst, litecov::RunResult};

/// [`TinyInst`](https://github.com/googleprojectzero/TinyInst) executor
pub struct TinyInstExecutor<S, SHM, OT> {
    tinyinst: TinyInst,
    coverage_ptr: *mut Vec<u64>,
    timeout: Duration,
    observers: OT,
    phantom: PhantomData<S>,
    cur_input: InputFile,
    map: Option<SHM>,
    /// Cumulative coverage tracking across all executions
    cumulative_coverage: HashSet<u64>,
}

impl TinyInstExecutor<(), NopShMem, ()> {
    /// Create a builder for [`TinyInstExecutor`]
    #[must_use]
    pub fn builder<'a>() -> TinyInstExecutorBuilder<'a, NopShMemProvider> {
        TinyInstExecutorBuilder::new()
    }
}

impl<S, SHM, OT> Debug for TinyInstExecutor<S, SHM, OT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("TinyInstExecutor")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl<EM, I, OT, S, SHM, Z> Executor<EM, I, S, Z> for TinyInstExecutor<S, SHM, OT>
where
    S: HasExecutions,
    I: HasTargetBytes,
    SHM: ShMem,
{
    #[inline]
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;
        match &self.map {
            Some(_) => {
                // use shmem to pass testcase
                let shmem = unsafe { self.map.as_mut().unwrap_unchecked() };
                let target_bytes = input.target_bytes();
                let size = target_bytes.as_slice().len();
                let size_in_bytes = size.to_ne_bytes();
                // The first four bytes tells the size of the shmem.
                shmem.as_slice_mut()[..SHMEM_FUZZ_HDR_SIZE]
                    .copy_from_slice(&size_in_bytes[..SHMEM_FUZZ_HDR_SIZE]);
                shmem.as_slice_mut()[SHMEM_FUZZ_HDR_SIZE..(SHMEM_FUZZ_HDR_SIZE + size)]
                    .copy_from_slice(target_bytes.as_slice());
            }
            None => {
                self.cur_input.write_buf(input.target_bytes().as_slice())?;
            }
        }

        #[expect(unused_assignments)]
        let mut status = RunResult::OK;
        unsafe {
            status = self.tinyinst.run();
            self.tinyinst
                .vec_coverage(self.coverage_ptr.as_mut().unwrap(), false);

            // Track cumulative coverage
            let coverage = self.coverage_ptr.as_ref().unwrap();
            for &offset in coverage {
                self.cumulative_coverage.insert(offset);
            }
        }

        match status {
            RunResult::CRASH => Ok(ExitKind::Crash),
            RunResult::HANG => Ok(ExitKind::Timeout),
            RunResult::OK => Ok(ExitKind::Ok),
            RunResult::OTHER_ERROR => Err(Error::unknown(
                "Tinyinst RunResult is other error".to_string(),
            )),
            _ => Err(Error::unknown("Tinyinst RunResult is unknown")),
        }
    }
}

/// Builder for `TinyInstExecutor`
#[derive(Debug)]
pub struct TinyInstExecutorBuilder<'a, SP> {
    tinyinst_args: Vec<String>,
    program_args: Vec<String>,
    timeout: Duration,
    coverage_ptr: *mut Vec<u64>,
    shmem_provider: Option<&'a mut SP>,
}

const MAX_FILE: usize = 1024 * 1024;
const SHMEM_FUZZ_HDR_SIZE: usize = 4;

impl Default for TinyInstExecutorBuilder<'_, NopShMemProvider> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> TinyInstExecutorBuilder<'a, NopShMemProvider> {
    /// Constructor
    #[must_use]
    pub fn new() -> TinyInstExecutorBuilder<'a, NopShMemProvider> {
        Self {
            tinyinst_args: vec![],
            program_args: vec![],
            timeout: Duration::new(3, 0),
            shmem_provider: None,
            coverage_ptr: ptr::null_mut(),
        }
    }

    /// Use this to enable shmem testcase passing.
    #[must_use]
    pub fn shmem_provider<SP>(self, shmem_provider: &'a mut SP) -> TinyInstExecutorBuilder<'a, SP> {
        TinyInstExecutorBuilder {
            tinyinst_args: self.tinyinst_args,
            program_args: self.program_args,
            timeout: self.timeout,
            shmem_provider: Some(shmem_provider),
            coverage_ptr: ptr::null_mut(),
        }
    }
}

impl<SP> TinyInstExecutorBuilder<'_, SP>
where
    SP: ShMemProvider,
{
    /// Argument for tinyinst instrumentation
    #[must_use]
    pub fn tinyinst_arg(mut self, arg: String) -> Self {
        self.tinyinst_args.push(arg);
        self
    }

    /// Arguments for tinyinst instrumentation
    #[must_use]
    pub fn tinyinst_args(mut self, args: Vec<String>) -> Self {
        for arg in args {
            self.tinyinst_args.push(arg);
        }
        self
    }

    /// The module to instrument.
    #[must_use]
    pub fn instrument_module(mut self, module: Vec<String>) -> Self {
        for modname in module {
            self.tinyinst_args.push("-instrument_module".to_string());
            self.tinyinst_args.push(modname);
        }
        self
    }

    /// Use shmem
    #[must_use]
    pub fn use_shmem(mut self) -> Self {
        self.tinyinst_args.push("-delivery".to_string());
        self.tinyinst_args.push("shmem".to_string());
        self
    }

    /// Persistent mode
    #[must_use]
    pub fn persistent(
        mut self,
        target_module: String,
        target_method: String,
        nargs: usize,
        iterations: usize,
    ) -> Self {
        self.tinyinst_args.push("-target_module".to_string());
        self.tinyinst_args.push(target_module);

        self.tinyinst_args.push("-target_method".to_string());
        self.tinyinst_args.push(target_method);

        self.tinyinst_args.push("-nargs".to_string());
        self.tinyinst_args.push(nargs.to_string());

        self.tinyinst_args.push("-iterations".to_string());
        self.tinyinst_args.push(iterations.to_string());

        self.tinyinst_args.push("-persist".to_string());
        self.tinyinst_args.push("-loop".to_string());
        self
    }

    /// Program arg
    #[must_use]
    pub fn program_arg(mut self, arg: String) -> Self {
        self.program_args.push(arg);
        self
    }

    /// Program args
    #[must_use]
    pub fn program_args(mut self, args: Vec<String>) -> Self {
        for arg in args {
            self.program_args.push(arg);
        }
        self
    }

    /// Set timeout
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the pointer to the coverage vec used to observer the execution.
    ///
    /// # Safety
    /// The coverage vec pointer must point to a valid vec and outlive the time the [`TinyInstExecutor`] is alive.
    /// The map will be dereferenced and borrowed mutably during execution. This may not happen concurrently.
    #[must_use]
    pub fn coverage_ptr(mut self, coverage_ptr: *mut Vec<u64>) -> Self {
        self.coverage_ptr = coverage_ptr;
        self
    }

    /// Enable comparison coverage (`-cmp_coverage`)
    ///
    /// Counts the number of bytes that match in cmp/sub instructions.
    #[must_use]
    pub fn cmp_coverage(mut self) -> Self {
        self.tinyinst_args.push("-cmp_coverage".to_string());
        self
    }

    /// Generate unwind information (`-generate_unwind`)
    ///
    /// Generates stack unwinding information for instrumented code
    /// and enables full sanitizer stack traces.
    #[must_use]
    pub fn generate_unwind(mut self) -> Self {
        self.tinyinst_args.push("-generate_unwind".to_string());
        self
    }

    /// Set target environment variable (`-target_env`)
    ///
    /// Sets an environment variable for the target process.
    #[must_use]
    pub fn target_env(mut self, key: &str, value: &str) -> Self {
        self.tinyinst_args.push("-target_env".to_string());
        self.tinyinst_args.push(format!("{key}={value}"));
        self
    }

    /// Set target offset (`-target_offset`)
    ///
    /// Specifies the offset of the target function within the target module.
    #[must_use]
    pub fn target_offset(mut self, offset: usize) -> Self {
        self.tinyinst_args.push("-target_offset".to_string());
        self.tinyinst_args.push(format!("0x{offset:x}"));
        self
    }

    /// Set indirect instrumentation mode (`-indirect_instrumentation`)
    ///
    /// Controls which instrumentation to use for indirect jump/calls.
    ///
    /// # Options
    /// - `"none"`: No indirect instrumentation
    /// - `"local"`: Per-callsite linked list (accurate edges, slower)
    /// - `"global"`: Global hashtable (better performance, default)
    /// - `"auto"`: Automatically choose (defaults to global on x86, local on ARM64)
    #[must_use]
    pub fn indirect_instrumentation(mut self, mode: &str) -> Self {
        self.tinyinst_args.push("-indirect_instrumentation".to_string());
        self.tinyinst_args.push(mode.to_string());
        self
    }

    /// Enable patching of return addresses (`-patch_return_addresses`)
    ///
    /// Patches return addresses on the stack to avoid breakpoint-based return handling.
    /// Can improve performance but may cause issues with some targets.
    #[must_use]
    pub fn patch_return_addresses(mut self) -> Self {
        self.tinyinst_args.push("-patch_return_addresses".to_string());
        self
    }

    /// Set stack offset (`-stack_offset`)
    ///
    /// Specifies additional stack space to reserve during instrumentation.
    #[must_use]
    pub fn stack_offset(mut self, offset: usize) -> Self {
        self.tinyinst_args.push("-stack_offset".to_string());
        self.tinyinst_args.push(offset.to_string());
        self
    }

    /// Set coverage type (`-covtype`)
    ///
    /// Specifies what type of coverage to collect.
    ///
    /// # Options
    /// - `"bb"`: Basic block coverage (default)
    /// - `"edge"`: Edge coverage
    #[must_use]
    pub fn coverage_type(mut self, covtype: &str) -> Self {
        self.tinyinst_args.push("-covtype".to_string());
        self.tinyinst_args.push(covtype.to_string());
        self
    }

    /// Build [`TinyInst`](https://github.com/googleprojectzero/TinyInst) executor
    pub fn build<OT, S>(
        &mut self,
        observers: OT,
    ) -> Result<TinyInstExecutor<S, SP::ShMem, OT>, Error> {
        if self.coverage_ptr.is_null() {
            return Err(Error::illegal_argument("Coverage pointer may not be null."));
        }
        let (map, shmem_id) = match &mut self.shmem_provider {
            Some(provider) => {
                // setup shared memory
                let mut shmem = provider.new_shmem(MAX_FILE + SHMEM_FUZZ_HDR_SIZE)?;
                let shmem_id = shmem.id();
                // log::trace!("{:#?}", shmem.id());
                // shmem.write_to_env("__TINY_SHM_FUZZ_ID")?;

                let size_in_bytes = (MAX_FILE + SHMEM_FUZZ_HDR_SIZE).to_ne_bytes();
                shmem.as_slice_mut()[..4].clone_from_slice(&size_in_bytes[..4]);

                (Some(shmem), Some(shmem_id))
            }
            None => (None, None),
        };

        let mut has_input = false;
        let program_args: Vec<String> = self
            .program_args
            .clone()
            .into_iter()
            .map(|arg| {
                if arg == "@@" {
                    has_input = true;
                    match shmem_id {
                        Some(shmem_name) => shmem_name.to_string(),
                        None => INPUTFILE_STD.to_string(),
                    }
                } else {
                    arg
                }
            })
            .collect();

        if !has_input {
            return Err(Error::unknown(
                "No input file or shmem provided".to_string(),
            ));
        }
        log::info!("tinyinst args: {:#?}", &self.tinyinst_args);

        let cur_input = InputFile::create(INPUTFILE_STD).expect("Unable to create cur_file");

        let tinyinst = TinyInst::new(
            &self.tinyinst_args,
            &program_args,
            self.timeout.as_millis() as u32,
        );

        Ok(TinyInstExecutor {
            tinyinst,
            coverage_ptr: self.coverage_ptr,
            timeout: self.timeout,
            observers,
            phantom: PhantomData,
            cur_input,
            map,
            cumulative_coverage: HashSet::new(),
        })
    }
}

impl<S, SHM, OT> HasObservers for TinyInstExecutor<S, SHM, OT> {
    type Observers = OT;

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<S, SHM, OT> TinyInstExecutor<S, SHM, OT> {
    /// Get the cumulative coverage set (all unique offsets seen across all executions)
    #[must_use]
    pub fn cumulative_coverage(&self) -> &HashSet<u64> {
        &self.cumulative_coverage
    }

    /// Get the count of unique offsets in cumulative coverage
    #[must_use]
    pub fn cumulative_coverage_count(&self) -> usize {
        self.cumulative_coverage.len()
    }

    /// Reset the cumulative coverage tracking
    pub fn reset_cumulative_coverage(&mut self) {
        self.cumulative_coverage.clear();
    }
}
