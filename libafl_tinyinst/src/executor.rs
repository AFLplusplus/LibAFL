use core::marker::PhantomData;
use std::{ffi::CString, os::raw::c_char};

use cxx::UniquePtr;
use libafl::{
    bolts::fs::{InputFile, INPUTFILE_STD},
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, UsesInput},
    observers::{ObserversTuple, UsesObservers},
    prelude::AsSlice,
    state::{State, UsesState},
    Error,
};

use crate::tinyinst::litecov::{get_coverage_map, Coverage, DebuggerStatus, LiteCov};

pub struct TinyInstExecutor<S, OT> {
    instrumentation_ptr: UniquePtr<LiteCov>,
    coverage_ptr: UniquePtr<Coverage>,
    argc: usize,
    argv: Vec<CString>,
    timeout: u32,
    observers: OT,
    phantom: PhantomData<S>,
    bitmap: *mut u8,
    map_size: usize,
    cur_input: InputFile,
    use_stdin: bool,
}

impl<S, OT> std::fmt::Debug for TinyInstExecutor<S, OT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TinyInstExecutor")
            .field("argc", &self.argc)
            .field("argv", &self.argv)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl<EM, S, Z, OT> Executor<EM, Z> for TinyInstExecutor<S, OT>
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
        let mut status = DebuggerStatus::DEBUGGER_NONE;
        unsafe {
            self.instrumentation_ptr.pin_mut().Kill();
            status = self.instrumentation_ptr.pin_mut().Run(
                self.argc as i32,
                argv.as_mut_ptr(),
                self.timeout,
            );

            self.instrumentation_ptr
                .pin_mut()
                .GetCoverage(self.coverage_ptr.pin_mut(), true);
            get_coverage_map(self.bitmap, self.map_size, self.coverage_ptr.pin_mut());
        }

        match status {
            DebuggerStatus::DEBUGGER_CRASHED | DebuggerStatus::DEBUGGER_HANGED => {
                Ok(ExitKind::Crash)
            }
            DebuggerStatus::DEBUGGER_NONE => {
                Err(Error::unknown("The harness was not run.".to_string()))
            }

            _ => Ok(ExitKind::Ok),
        }
    }
}

impl<S, OT> TinyInstExecutor<S, OT>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    pub unsafe fn new(
        tinyinst_args: Vec<String>,
        args: Vec<String>,
        timeout: u32,
        observers: OT,
        bitmap: *mut u8,
        map_size: usize,
    ) -> Self {
        let mut instrumentation_ptr = LiteCov::new();
        let instrumentation = instrumentation_ptr.pin_mut();

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

        instrumentation.Init(tinyinst_argc as i32, tinyinst_argv.as_mut_ptr());
        println!("post init");

        let coverage_ptr = Coverage::new();

        Self {
            instrumentation_ptr,
            coverage_ptr,
            argc,
            argv: argv_vec_cstr,
            timeout,
            observers,
            phantom: PhantomData,
            bitmap,
            map_size,
            cur_input,
            use_stdin,
        }
    }
}

impl<S, OT> HasObservers for TinyInstExecutor<S, OT>
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
impl<S, OT> UsesState for TinyInstExecutor<S, OT>
where
    S: UsesInput,
{
    type State = S;
}
impl<S, OT> UsesObservers for TinyInstExecutor<S, OT>
where
    OT: ObserversTuple<S>,
    S: UsesInput,
{
    type Observers = OT;
}
