use core::marker::PhantomData;

use libafl::{
    bolts::fs::{InputFile, INPUTFILE_STD},
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, UsesInput},
    observers::{ObserversTuple, UsesObservers},
    prelude::AsSlice,
    state::{State, UsesState},
    Error,
};
use tinyinst_rs::tinyinst::{litecov::RunResult, TinyInst};

pub struct TinyInstExecutor<'a, S, OT> {
    tinyinst: TinyInst,
    coverage: &'a mut Vec<u64>,
    timeout: u32,
    observers: OT,
    phantom: PhantomData<S>,
    cur_input: InputFile,
    use_stdin: bool,
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
        if !self.use_stdin {
            self.cur_input.write_buf(input.target_bytes().as_slice())?;
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

impl<'a, S, OT> TinyInstExecutor<'a, S, OT>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    ///  # Safety
    pub unsafe fn new(
        coverage: &'a mut Vec<u64>,
        tinyinst_args: Vec<String>,
        program_args: Vec<String>,
        timeout: u32,
        observers: OT,
    ) -> Self {
        let mut use_stdin = true;

        let program_args = program_args
            .into_iter()
            .map(|arg| {
                if arg == "@@" {
                    println!("Not using stdin");
                    use_stdin = false;
                    INPUTFILE_STD.to_string()
                } else {
                    arg
                }
            })
            .collect();

        let cur_input = InputFile::create(INPUTFILE_STD).expect("Unable to create cur_file");
        println!("post init");
        let tinyinst = TinyInst::new(tinyinst_args, program_args, timeout);

        Self {
            tinyinst,
            coverage,
            timeout,
            observers,
            phantom: PhantomData,
            cur_input,
            use_stdin,
        }
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
