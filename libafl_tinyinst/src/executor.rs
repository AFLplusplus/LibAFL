use core::marker::PhantomData;
use core::pin::Pin;
use std::{ffi::CString, os::raw::c_char};

use cxx::UniquePtr;
use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    state::State,
    Error,
};

use crate::tinyinst::litecov::{self, Coverage, DebuggerStatus, LiteCov};

pub struct TinyInstExecutor<I, OT, S>
where
    OT: ObserversTuple<I, S>,
{
    instrumentation_ptr: UniquePtr<LiteCov>,
    coverage_ptr: UniquePtr<Coverage>,
    newcoverage_ptr: UniquePtr<Coverage>,
    argc: usize,
    argv: Vec<*mut c_char>,
    timeout: u32,
    observers: OT,
    phantom: PhantomData<(I, S, OT)>,
}

impl<I, OT, S> std::fmt::Debug for TinyInstExecutor<I, OT, S>
where
    OT: ObserversTuple<I, S>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TinyInstExecutor")
            .field("argc", &self.argc)
            .field("argv", &self.argv)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl<EM, I, S, Z, OT> Executor<EM, I, S, Z> for TinyInstExecutor<I, OT, S>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple<I, S>,
{
    #[inline]
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) -> Result<ExitKind, Error> {
        let mut status: DebuggerStatus = DebuggerStatus::DEBUGGER_NONE;
        self.observers.pre_exec_all(_state, _input)?;

        unsafe {
            status = self.instrumentation_ptr.pin_mut().Run(
                self.argc as i32,
                self.argv.as_mut_ptr(),
                self.timeout,
            );
        }

        match status {
            DebuggerStatus::DEBUGGER_CRASHED | DebuggerStatus::DEBUGGER_HANGED => {
                // set the observer here
                Ok(ExitKind::Crash)
            }
            DebuggerStatus::DEBUGGER_NONE => {
                Err(Error::unknown("The harness was not run.".to_string()))
            }
            _ => Ok(ExitKind::Ok),
        }
    }
}

impl<I, OT, S> TinyInstExecutor<I, OT, S>
where
    OT: ObserversTuple<I, S>,
{
    pub unsafe fn new(args: Vec<String>, timeout: u32, observers: OT) -> Self {
        let mut instrumentation_ptr = LiteCov::new();
        let instrumentation = instrumentation_ptr.pin_mut();

        let argc = args.len();
        let vec_cstr: Vec<CString> = args
            .iter()
            .map(|arg| CString::new(arg.as_str()).unwrap())
            .collect();
        let mut argv: Vec<*mut c_char> = Vec::with_capacity(argc + 1);
        for arg in &vec_cstr {
            argv.push(arg.as_ptr() as *mut c_char);
        }
        argv.push(core::ptr::null_mut()); //Null terminator
        println!("initing {} {:?}", &argc, &argv);
        for c in &argv {
            println!("{:?}", c);
        }

        instrumentation.Init(argc as i32, argv.as_mut_ptr());
        println!("post init");

        let coverage_ptr = Coverage::new();
        let newcoverage_ptr = Coverage::new();

        Self {
            instrumentation_ptr,
            coverage_ptr,
            newcoverage_ptr,
            argc,
            argv,
            timeout,
            observers,
            phantom: PhantomData,
        }
    }
}

impl<I, OT, S> HasObservers<I, OT, S> for TinyInstExecutor<I, OT, S>
where
    I: Input,
    OT: ObserversTuple<I, S>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
