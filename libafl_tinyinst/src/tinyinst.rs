use std::os::raw::c_char;

#[cxx::bridge]
pub mod common {
    // C++ types and signatures exposed to Rust.
    unsafe extern "C++" {
        include!("common.h");
        fn GetCurTime() -> u64;
    }
}

#[cxx::bridge]
pub mod litecov {
    #[repr(u32)]
    enum DebuggerStatus {
        DEBUGGER_NONE,
        DEBUGGER_CONTINUE,
        DEBUGGER_PROCESS_EXIT,
        DEBUGGER_TARGET_START,
        DEBUGGER_TARGET_END,
        DEBUGGER_CRASHED,
        DEBUGGER_HANGED,
        DEBUGGER_ATTACHED
    }

    unsafe extern "C++"{
        include!("litecov.h");
        include!("coverage.h");
        // for constructors.
        include!("shim.h");

        type ModuleCovData;
        pub fn ClearInstrumentationData(self: Pin<&mut ModuleCovData>);
        pub fn ClearCmpCoverageData(self: Pin<&mut ModuleCovData>);

        type LiteCov;
        type Coverage;
        type ModuleCoverage;

        pub fn coverage_new() -> UniquePtr<Coverage>;

        // class LiteCov
        pub fn litecov_new() -> UniquePtr<LiteCov>;

        pub unsafe fn Init(self: Pin<&mut LiteCov>, argc: i32, argv: *mut *mut c_char);
        pub fn GetCoverage(self: Pin<&mut LiteCov>, coverage: Pin<&mut Coverage>, clear_coverage: bool);
        pub fn IgnoreCoverage(self: Pin<&mut LiteCov>, coverage: Pin<&mut Coverage>);
        pub fn ClearCoverage(self: Pin<&mut LiteCov>);
        pub fn HasNewCoverage(self: Pin<&mut LiteCov>) -> bool;

        // class TinyInst
        pub fn EnableInstrumentation(self: Pin<&mut LiteCov>);
        pub fn DisableInstrumentation(self: Pin<&mut LiteCov>);

        type DebuggerStatus;
        // class Debugger
        // pub unsafe fn Run(self: Pin<&mut LiteCov>, cmd: *mut c_char, timeout: u32) -> DebuggerStatus;
        pub unsafe fn Run(self: Pin<&mut LiteCov>, argc: i32, argv: *mut *mut c_char, timeout: u32) -> DebuggerStatus;
        pub fn Kill(self: Pin<&mut LiteCov>) -> DebuggerStatus;
        pub fn Continue(self: Pin<&mut LiteCov>, timeout: u32) -> DebuggerStatus;
        pub fn Attach(self: Pin<&mut LiteCov>, pid: u32, timeout: u32) -> DebuggerStatus;

        pub fn IsTargetAlive(self: Pin<&mut LiteCov>) -> bool;
        pub fn IsTargetFunctionDefined(self: Pin<&mut LiteCov>) -> bool;
        pub fn GetTargetReturnValue(self: Pin<&mut LiteCov>) -> u64;

    }
}

use cxx::UniquePtr;
impl litecov::LiteCov {
    pub fn new() -> UniquePtr<litecov::LiteCov> {
        litecov::litecov_new()
    }
}

impl litecov::Coverage {
    pub fn new() -> UniquePtr<litecov::Coverage> {
        litecov::coverage_new()
    }
}