use crate::tinyinst::litecov::{self, Coverage, DebuggerStatus, LiteCov};
use cxx::UniquePtr;
use core::pin::Pin;
use libafl::{
    executors::{Executor, ExitKind},
    inputs::Input,
    Error,
};
use std::{ffi::CString, os::raw::c_char};

pub struct TinyInstExecutor {
    instrumentation_ptr: UniquePtr<LiteCov>,
    coverage_ptr: UniquePtr<Coverage>,
    newcoverage_ptr: UniquePtr<Coverage>,
    argc: usize,
    argv: Vec<*mut c_char>,
    timeout: u32,
}

impl<EM, I, S, Z> Executor<EM, I, S, Z> for TinyInstExecutor
where
I: Input,
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

        unsafe {
            status = self.instrumentation_ptr.pin_mut().Run(self.argc as i32, self.argv.as_mut_ptr(), self.timeout);
        }

        match status {
            DebuggerStatus::DEBUGGER_CRASHED | DebuggerStatus::DEBUGGER_HANGED => {
                Ok(ExitKind::Crash)
            },
            DebuggerStatus::DEBUGGER_NONE => {
                Err(Error::Unknown("The harness was not run.".to_string()))
            },
            _ => {
                Ok(ExitKind::Ok)
            }
        }
    }
}

impl TinyInstExecutor {
    pub unsafe fn new(args: Vec<String>, timeout: u32) -> Self {
        let mut instrumentation_ptr = LiteCov::new();
        let instrumentation = instrumentation_ptr.pin_mut(); 

        let argc = args.len() + 1;
        let vec_cstr : Vec<CString> = args.iter()
            .map(|arg| CString::new(arg.as_str()).unwrap())
            .collect();
        let mut argv: Vec<*mut c_char> = Vec::with_capacity(argc + 1);
        for arg in &vec_cstr {
            argv.push(arg.as_ptr() as *mut c_char);
        }
        argv.push(core::ptr::null_mut()); //Null terminator
        instrumentation.Init(argc as i32, argv.as_mut_ptr());

        let coverage_ptr = Coverage::new();
        let newcoverage_ptr = Coverage::new();

        Self {
            instrumentation_ptr,
            coverage_ptr,
            newcoverage_ptr,
            argc,            
            argv,
            timeout,
        }
    }
}