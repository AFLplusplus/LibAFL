use core::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
    ptr,
    time::Duration,
};

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

const MAX_FILE: usize = 1024 * 1024;
const SHMEM_FUZZ_HDR_SIZE: usize = 4;

/// Executor wrapping [TinyInst](https://github.com/googleprojectzero/TinyInst)
/// for binary-only coverage-guided fuzzing.
///
/// Supports file-based and shared memory testcase delivery, as well as persistent
/// mode. Construct via [`TinyInstExecutor::builder`] -> [`TinyInstExecutorBuilder`].
pub struct TinyInstExecutor<S, SHM, OT> {
    tinyinst: TinyInst,
    // Invariant: non-null, points to a valid Vec<u64>, valid for the executor's
    // lifetime, not accessed concurrently during execution.
    coverage_ptr: *mut Vec<u64>,
    timeout: Duration,
    observers: OT,
    phantom: PhantomData<S>,
    cur_input: InputFile,
    map: Option<SHM>,
}

impl TinyInstExecutor<(), NopShMem, ()> {
    /// Returns a builder for [`TinyInstExecutor`].
    ///
    /// Configure instrumentation args, program args, timeout, and coverage pointer
    /// before calling [`TinyInstExecutorBuilder::build`].
    #[must_use]
    pub fn builder<'a>() -> TinyInstExecutorBuilder<'a, NopShMemProvider> {
        TinyInstExecutorBuilder::new()
    }
}

impl<S, SHM, OT> Debug for TinyInstExecutor<S, SHM, OT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
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
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        if let Some(shmem) = &mut self.map {
            let target_bytes = input.target_bytes();
            let size = target_bytes.as_slice().len();
            let size_in_bytes = size.to_ne_bytes();
            shmem.as_slice_mut()[..SHMEM_FUZZ_HDR_SIZE]
                .copy_from_slice(&size_in_bytes[..SHMEM_FUZZ_HDR_SIZE]);
            shmem.as_slice_mut()[SHMEM_FUZZ_HDR_SIZE..(SHMEM_FUZZ_HDR_SIZE + size)]
                .copy_from_slice(target_bytes.as_slice());
        } else {
            self.cur_input.write_buf(input.target_bytes().as_slice())?;
        }

        // SAFETY: coverage_ptr is validated as non-null in the builder.
        let status = unsafe {
            let s = self.tinyinst.run();
            self.tinyinst.vec_coverage(&mut *self.coverage_ptr, false);
            s
        };

        match status {
            RunResult::CRASH | RunResult::HANG => Ok(ExitKind::Crash),
            RunResult::OK => Ok(ExitKind::Ok),
            RunResult::OTHER_ERROR => Err(Error::unknown("Tinyinst RunResult is other error")),
            _ => Err(Error::unknown("Tinyinst RunResult is unknown")),
        }
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

/// Builder for [`TinyInstExecutor`].
///
/// # Example
/// ```no_run
/// # use std::time::Duration;
/// # use libafl_tinyinst::executor::TinyInstExecutor;
/// # use libafl::observers::ListObserver;
/// # use libafl_bolts::{ownedref::OwnedMutPtr, tuples::tuple_list};
/// # fn main() -> Result<(), libafl::Error> {
/// static mut COVERAGE: Vec<u64> = Vec::new();
///
/// let observer = ListObserver::new("cov", OwnedMutPtr::Ptr(&raw mut COVERAGE));
/// let mut executor = TinyInstExecutor::builder()
///     .instrument_module(["target.dll"])
///     .program_args(["./target", "@@"])
///     .timeout(Duration::from_secs(5))
///     .coverage_ptr(&raw mut COVERAGE)
///     .build::<_, ()>(tuple_list!(observer))?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct TinyInstExecutorBuilder<'a, SP> {
    tinyinst_args: Vec<String>,
    program_args: Vec<String>,
    timeout: Duration,
    coverage_ptr: *mut Vec<u64>,
    shmem_provider: Option<&'a mut SP>,
}

impl Default for TinyInstExecutorBuilder<'_, NopShMemProvider> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> TinyInstExecutorBuilder<'a, NopShMemProvider> {
    /// Creates a new builder without shared memory support.
    ///
    /// Use [`Self::shmem_provider`] to enable shmem-based testcase delivery.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tinyinst_args: vec![],
            program_args: vec![],
            timeout: Duration::new(3, 0),
            shmem_provider: None,
            coverage_ptr: ptr::null_mut(),
        }
    }

    /// Enables shared memory testcase delivery using the given provider.
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

impl<SP: ShMemProvider> TinyInstExecutorBuilder<'_, SP> {
    /// Appends a single argument to the `TinyInst` instrumentation command line.
    #[must_use]
    pub fn tinyinst_arg(mut self, arg: impl Into<String>) -> Self {
        self.tinyinst_args.push(arg.into());
        self
    }

    /// Appends multiple arguments to the `TinyInst` instrumentation command line.
    #[must_use]
    pub fn tinyinst_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tinyinst_args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Registers one or more modules for instrumentation (`-instrument_module <name>`).
    #[must_use]
    pub fn instrument_module(
        mut self,
        modules: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        for name in modules {
            self.tinyinst_args.push("-instrument_module".to_string());
            self.tinyinst_args.push(name.into());
        }
        self
    }

    /// Configures testcase delivery over shared memory (`-delivery shmem`).
    #[must_use]
    pub fn use_shmem(mut self) -> Self {
        self.tinyinst_args.push("-delivery".to_string());
        self.tinyinst_args.push("shmem".to_string());
        self
    }

    /// Enables persistent fuzzing mode, looping over `target_method` in `target_module`
    /// for `iterations` rounds with `nargs` arguments per call.
    #[must_use]
    pub fn persistent(
        mut self,
        target_module: impl Into<String>,
        target_method: impl Into<String>,
        nargs: usize,
        iterations: usize,
    ) -> Self {
        self.tinyinst_args.extend([
            "-target_module".to_string(),
            target_module.into(),
            "-target_method".to_string(),
            target_method.into(),
            "-nargs".to_string(),
            nargs.to_string(),
            "-iterations".to_string(),
            iterations.to_string(),
            "-persist".to_string(),
            "-loop".to_string(),
        ]);
        self
    }

    /// Appends a single argument to the target program's command line.
    #[must_use]
    pub fn program_arg(mut self, arg: impl Into<String>) -> Self {
        self.program_args.push(arg.into());
        self
    }

    /// Appends multiple arguments to the target program's command line.
    ///
    /// Use `"@@"` as a placeholder for the input.
    #[must_use]
    pub fn program_args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.program_args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Sets the per-execution timeout. Defaults to 3 seconds.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the pointer to the coverage vector populated after each execution.
    ///
    /// The pointer must be non-null, point to a valid `Vec<u64>`, and remain
    /// valid for the entire lifetime of the resulting [`TinyInstExecutor`].
    /// The vector must not be accessed concurrently with execution.
    ///
    /// Nullness is checked at [`build`](Self::build) time; all other invariants
    /// are the caller's responsibility.
    #[must_use]
    pub fn coverage_ptr(mut self, coverage_ptr: *mut Vec<u64>) -> Self {
        self.coverage_ptr = coverage_ptr;
        self
    }

    /// Builds the [`TinyInstExecutor`].
    ///
    /// Fails if `coverage_ptr` is null or `"@@"` does not appear in the
    /// program arguments.
    pub fn build<OT, S>(
        &mut self,
        observers: OT,
    ) -> Result<TinyInstExecutor<S, SP::ShMem, OT>, Error> {
        if self.coverage_ptr.is_null() {
            return Err(Error::illegal_argument("Coverage pointer may not be null."));
        }

        let (map, shmem_id) = match &mut self.shmem_provider {
            Some(provider) => {
                let mut shmem = provider.new_shmem(MAX_FILE + SHMEM_FUZZ_HDR_SIZE)?;
                let shmem_id = shmem.id();
                let size_in_bytes = (MAX_FILE + SHMEM_FUZZ_HDR_SIZE).to_ne_bytes();
                shmem.as_slice_mut()[..4].copy_from_slice(&size_in_bytes[..4]);
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
                    shmem_id
                        .as_ref()
                        .map_or_else(|| INPUTFILE_STD.to_string(), ToString::to_string)
                } else {
                    arg
                }
            })
            .collect();

        if !has_input {
            return Err(Error::unknown("No input file or shmem provided"));
        }

        log::info!("tinyinst args: {:#?}", &self.tinyinst_args);

        let cur_input = InputFile::create(INPUTFILE_STD)?;
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
        })
    }
}
