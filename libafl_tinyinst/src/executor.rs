use core::marker::PhantomData;
use std::{ffi::CString, os::raw::c_char};

use libafl::{
    bolts::fs::{InputFile, INPUTFILE_STD},
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, UsesInput},
    observers::{ObserversTuple, UsesObservers},
    prelude::AsSlice,
    state::{State, UsesState},
    Error,
};

use tinyinst_rs::tinyinst::litecov::RunResult;
use tinyinst_rs::tinyinst::TinyInst;

pub struct TinyInstExecutor<'a, S, OT> {
    tinyinst: TinyInst,
    coverage: &'a mut Vec<u64>,
    argc: usize,
    argv: Vec<CString>,
    timeout: u32,
    observers: OT,
    phantom: PhantomData<S>,
    cur_input: InputFile,
    use_stdin: bool,
}

impl<'a, S, OT> std::fmt::Debug for TinyInstExecutor<'a, S, OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TinyInstExecutor")
            .field("argc", &self.argc)
            .field("argv", &self.argv)
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
        let mut argv: Vec<*mut c_char> = Vec::with_capacity(self.argc + 1);

        for arg in &self.argv {
            argv.push(arg.as_ptr() as *mut c_char);
        }
        argv.push(core::ptr::null_mut());

        if !self.use_stdin {
            self.cur_input.write_buf(input.target_bytes().as_slice())?;
        }

        #[allow(unused_assignments)]
        let mut status = RunResult::OK;
        unsafe {
            status = self.tinyinst.run();
            self.tinyinst.vec_coverage(self.coverage, false);
            println!("Coverage: {:?}", &self.coverage[100]);
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
    pub unsafe fn new(
        coverage: &'a mut Vec<u64>,
        tinyinst_args: Vec<String>,
        args: Vec<String>,
        timeout: u32,
        observers: OT,
    ) -> Self {
        // Convert args into c string vector
        let argc = args.len();
        let mut use_stdin = true;

        let argv_vec_cstr: Vec<CString> = args
            .iter()
            .map(|arg| {
                if arg == "@@" {
                    println!("Not using stdin");
                    use_stdin = false;
                    CString::new(INPUTFILE_STD).unwrap()
                } else {
                    CString::new(arg.as_str()).unwrap()
                }
            })
            .collect();

        let cur_input = InputFile::create(INPUTFILE_STD).expect("Unable to create cur_file");
        let mut argv: Vec<*mut c_char> = Vec::with_capacity(argc + 1);
        for arg in &argv_vec_cstr {
            argv.push(arg.as_ptr() as *mut c_char);
        }
        argv.push(core::ptr::null_mut()); //Null terminator

        // Get tinyinst argv and argc
        let tinyinst_argc = tinyinst_args.len();
        let vec_cstr: Vec<CString> = tinyinst_args
            .iter()
            .map(|arg| CString::new(arg.as_str()).unwrap())
            .collect();

        let mut tinyinst_argv: Vec<*mut c_char> = Vec::with_capacity(tinyinst_argc + 1);
        for arg in &vec_cstr {
            tinyinst_argv.push(arg.as_ptr() as *mut c_char);
        }
        tinyinst_argv.push(core::ptr::null_mut()); //Null terminator

        println!("initing {} {:?}", &argc, &argv);

        println!("post init");
        let tinyinst = TinyInst::new(tinyinst_args, args, timeout);

        Self {
            tinyinst,
            coverage,
            argc,
            argv: argv_vec_cstr,
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
