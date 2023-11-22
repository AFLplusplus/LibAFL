use core::marker::PhantomData;
use std::time::Duration;

use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::HasTargetBytes,
    observers::{ObserversTuple, UsesObservers},
    state::{HasExecutions, State, UsesState},
    Error,
};
use libafl_bolts::{
    fs::{InputFile, INPUTFILE_STD},
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    AsMutSlice, AsSlice,
};
use tinyinst::tinyinst::{litecov::RunResult, TinyInst};

/// Tinyinst executor
pub struct TinyInstExecutor<'a, S, SP, OT>
where
    SP: ShMemProvider,
{
    tinyinst: TinyInst,
    coverage: &'a mut Vec<u64>,
    timeout: Duration,
    observers: OT,
    phantom: PhantomData<S>,
    cur_input: InputFile,
    map: Option<<SP as ShMemProvider>::ShMem>,
}

impl<'a, S, SP, OT> std::fmt::Debug for TinyInstExecutor<'a, S, SP, OT>
where
    SP: ShMemProvider,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TinyInstExecutor")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl<'a, EM, S, SP, OT, Z> Executor<EM, Z> for TinyInstExecutor<'a, S, SP, OT>
where
    EM: UsesState<State = S>,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    SP: ShMemProvider,
    Z: UsesState<State = S>,
{
    #[inline]
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
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
                shmem.as_mut_slice()[..SHMEM_FUZZ_HDR_SIZE]
                    .copy_from_slice(&size_in_bytes[..SHMEM_FUZZ_HDR_SIZE]);
                shmem.as_mut_slice()[SHMEM_FUZZ_HDR_SIZE..(SHMEM_FUZZ_HDR_SIZE + size)]
                    .copy_from_slice(target_bytes.as_slice());
            }
            None => {
                self.cur_input.write_buf(input.target_bytes().as_slice())?;
            }
        }

        #[allow(unused_assignments)]
        let mut status = RunResult::OK;
        unsafe {
            status = self.tinyinst.run();
            self.tinyinst.vec_coverage(self.coverage, false);
        }

        match status {
            RunResult::CRASH | RunResult::HANG => Ok(ExitKind::Crash),
            RunResult::OK => Ok(ExitKind::Ok),
            RunResult::OTHER_ERROR => Err(Error::unknown(
                "Tinyinst RunResult is other error".to_string(),
            )),
            _ => Err(Error::unknown("Tinyinst RunResult is unknown".to_string())),
        }
    }
}

/// Builder for `TinyInstExecutor`
#[derive(Debug)]
pub struct TinyInstExecutorBuilder<'a, SP> {
    tinyinst_args: Vec<String>,
    program_args: Vec<String>,
    timeout: Duration,
    shmem_provider: Option<&'a mut SP>,
}

const MAX_FILE: usize = 1024 * 1024;
const SHMEM_FUZZ_HDR_SIZE: usize = 4;

impl<'a> Default for TinyInstExecutorBuilder<'a, StdShMemProvider> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> TinyInstExecutorBuilder<'a, StdShMemProvider> {
    /// Constructor
    #[must_use]
    pub fn new() -> TinyInstExecutorBuilder<'a, StdShMemProvider> {
        Self {
            tinyinst_args: vec![],
            program_args: vec![],
            timeout: Duration::new(3, 0),
            shmem_provider: None,
        }
    }

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

    /// Use this to enable shmem testcase passing.
    #[must_use]
    pub fn shmem_provider<SP: ShMemProvider>(
        self,
        shmem_provider: &'a mut SP,
    ) -> TinyInstExecutorBuilder<'a, SP> {
        TinyInstExecutorBuilder {
            tinyinst_args: self.tinyinst_args,
            program_args: self.program_args,
            timeout: self.timeout,
            shmem_provider: Some(shmem_provider),
        }
    }
}

impl<'a, SP> TinyInstExecutorBuilder<'a, SP>
where
    SP: ShMemProvider,
{
    /// Build tinyinst executor
    pub fn build<OT, S>(
        &mut self,
        coverage: &'a mut Vec<u64>,
        observers: OT,
    ) -> Result<TinyInstExecutor<'a, S, SP, OT>, Error> {
        let (map, shmem_id) = match &mut self.shmem_provider {
            Some(provider) => {
                // setup shared memory
                let mut shmem = provider.new_shmem(MAX_FILE + SHMEM_FUZZ_HDR_SIZE)?;
                let shmem_id = shmem.id();
                // log::trace!("{:#?}", shmem.id());
                // shmem.write_to_env("__TINY_SHM_FUZZ_ID")?;

                let size_in_bytes = (MAX_FILE + SHMEM_FUZZ_HDR_SIZE).to_ne_bytes();
                shmem.as_mut_slice()[..4].clone_from_slice(&size_in_bytes[..4]);

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

        let tinyinst = unsafe {
            TinyInst::new(
                &self.tinyinst_args,
                &program_args,
                self.timeout.as_millis() as u32,
            )
        };

        Ok(TinyInstExecutor {
            tinyinst,
            coverage,
            timeout: self.timeout,
            observers,
            phantom: PhantomData,
            cur_input,
            map,
        })
    }
}

impl<'a, S, SP, OT> HasObservers for TinyInstExecutor<'a, S, SP, OT>
where
    S: State,
    SP: ShMemProvider,
    OT: ObserversTuple<S>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
impl<'a, S, SP, OT> UsesState for TinyInstExecutor<'a, S, SP, OT>
where
    S: State,
    SP: ShMemProvider,
{
    type State = S;
}
impl<'a, S, SP, OT> UsesObservers for TinyInstExecutor<'a, S, SP, OT>
where
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
{
    type Observers = OT;
}
