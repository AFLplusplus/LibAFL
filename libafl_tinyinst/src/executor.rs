use core::marker::PhantomData;
use std::time::Duration;

use libafl::{
    bolts::{
        fs::{InputFile, INPUTFILE_STD},
        shmem::{ShMem, ShMemId, ShMemProvider},
        AsMutSlice, AsSlice,
    },
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, UsesInput},
    observers::{ObserversTuple, UsesObservers},
    state::{State, UsesState},
    Error,
};
use tinyinst::tinyinst::{litecov::RunResult, TinyInst};

pub struct TinyInstExecutor<'a, S, OT> {
    tinyinst: TinyInst,
    coverage: &'a mut Vec<u64>,
    timeout: Duration,
    observers: OT,
    phantom: PhantomData<S>,
    cur_input: InputFile,
    shmem_id: Option<ShMemId>,
}

impl<'a, S, OT> std::fmt::Debug for TinyInstExecutor<'a, S, OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TinyInstExecutor")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl<'a, EM, S, Z, OT> Executor<EM, Z> for TinyInstExecutor<'a, S, OT>
where
    EM: UsesState<State = S>,
    S: UsesInput,
    S::Input: HasTargetBytes,
    Z: UsesState<State = S>,
{
    #[inline]
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        match self.shmem_id {
            Some(id) => {
                // use shmem to pass testcase
                // TODO: write bytes into the shmem map
                self.cur_input.write_buf(input.target_bytes().as_slice())?;
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

#[derive(Debug)]
pub struct TinyInstExecutorBuilder<'a, SP> {
    tinyinst_args: Vec<String>,
    program_args: Vec<String>,
    timeout: Duration,
    shmem_provider: Option<&'a mut SP>,
}

const MAX_FILE: usize = 1024 * 1024;
const SHMEM_FUZZ_HDR_SIZE: usize = 4;

impl<'a, SP> TinyInstExecutorBuilder<'a, SP>
where
    SP: ShMemProvider,
{
    pub fn new() -> TinyInstExecutorBuilder<'a, SP> {
        Self {
            tinyinst_args: vec![],
            program_args: vec![],
            timeout: Duration::new(3, 0),
            shmem_provider: None,
        }
    }

    pub fn tinyinst_arg(mut self, arg: String) -> Self {
        self.tinyinst_args.push(arg);
        self
    }

    pub fn tinyinst_args(mut self, args: Vec<String>) -> Self {
        for arg in args {
            self.tinyinst_args.push(arg);
        }
        self
    }

    pub fn instrument_module(mut self, module: Vec<String>) -> Self {
        for modname in module {
            self.tinyinst_args.push("-instrument_module".to_string());
            self.tinyinst_args.push(modname)
        }
        self
    }

    pub fn use_shmem(mut self) -> Self {
        self.tinyinst_args.push("-delivery".to_string());
        self.tinyinst_args.push("shmem".to_string());
        self
    }

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

    pub fn program_arg(mut self, arg: String) -> Self {
        self.program_args.push(arg);
        self
    }

    pub fn program_args(mut self, args: Vec<String>) -> Self {
        for arg in args {
            self.program_args.push(arg);
        }
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn shmem_provider(mut self, shmem_provider: &'a mut SP) -> Self {
        self.shmem_provider = Some(shmem_provider);
        self
    }

    pub fn build<OT, S>(
        &mut self,
        coverage: &'a mut Vec<u64>,
        observers: OT,
    ) -> Result<TinyInstExecutor<'a, S, OT>, Error> {
        let mut has_input = false;
        let program_args: Vec<String> = self
            .program_args
            .clone()
            .into_iter()
            .map(|arg| {
                if arg == "@@" {
                    has_input = true;
                    INPUTFILE_STD.to_string()
                } else {
                    arg
                }
            })
            .collect();
        if !has_input {
            return Err(Error::unknown(format!("No input file or shmem provided")));
        }
        println!("tinyinst args: {:#?}", &self.tinyinst_args);

        let cur_input = InputFile::create(INPUTFILE_STD).expect("Unable to create cur_file");

        let shmem_id = match &mut self.shmem_provider {
            Some(provider) => {
                // setup shared memory
                let mut shmem = provider.new_shmem(MAX_FILE + SHMEM_FUZZ_HDR_SIZE)?;
                // TODO: Replace .cur_input with shmem.id()
                println!("{:#?}", shmem.id());
                // shmem.write_to_env("__AFL_SHM_FUZZ_ID")?;

                let size_in_bytes = (MAX_FILE + SHMEM_FUZZ_HDR_SIZE).to_ne_bytes();
                shmem.as_mut_slice()[..4].clone_from_slice(&size_in_bytes[..4]);

                Some(shmem.id())
            }
            None => None,
        };

        let tinyinst = unsafe {
            TinyInst::new(
                &self.tinyinst_args,
                &program_args,
                self.timeout.as_millis() as u32,
            )
        };

        Ok(TinyInstExecutor {
            tinyinst: tinyinst,
            coverage: coverage,
            timeout: self.timeout,
            observers: observers,
            phantom: PhantomData,
            cur_input,
            shmem_id,
        })
    }
}

impl<'a, S, OT> HasObservers for TinyInstExecutor<'a, S, OT>
where
    S: State,
    OT: ObserversTuple<S>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
impl<'a, S, OT> UsesState for TinyInstExecutor<'a, S, OT>
where
    S: UsesInput,
{
    type State = S;
}
impl<'a, S, OT> UsesObservers for TinyInstExecutor<'a, S, OT>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    type Observers = OT;
}
