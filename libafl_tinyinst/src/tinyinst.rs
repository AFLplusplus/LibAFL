#[cxx::bridge]
pub mod common {
    // C++ types and signatures exposed to Rust.
    unsafe extern "C++" {
        include!("common.h");
        fn GetCurTime() -> u64;
    }
}

// #[cxx::bridge]
// pub mod tinyinst {
//     #[repr(u32)]
//     enum RunResult {
//         OK,
//         CRASH,
//         HANG,
//         OTHER_ERROR,
//     }

//     unsafe extern "C++" {
//         include!("tinyinstinstrumentation.h");
//         // for constructors
//         include!("shim.h");
//         include!("coverage.h");
//         type TinyInstInstrumentation;
//         pub fn tinyinstinstrumentation_new() -> UniquePtr<TinyInstInstrumentation>;

//         type RunResult;
//         // type Coverage;
//         pub unsafe fn Init(
//             self: Pin<&mut TinyInstInstrumentation>,
//             argc: i32,
//             argv: *mut *mut c_char,
//         );
//         pub unsafe fn Run(
//             self: Pin<&mut TinyInstInstrumentation>,
//             argc: i32,
//             argv: *mut *mut c_char,
//             init_timeout: u32,
//             timeout: u32,
//         ) -> RunResult;

//         pub unsafe fn RunWithCrashAnalysis(
//             self: Pin<&mut TinyInstInstrumentation>,
//             argc: i32,
//             argv: *mut *mut c_char,
//             init_timeout: u32,
//             timeout: u32,
//         ) -> RunResult;

//         pub fn CleanTarget(self: Pin<&mut TinyInstInstrumentation>);
//         pub fn HasNewCoverage(self: Pin<&mut TinyInstInstrumentation>) -> bool;

//         // pub fn GetCoverage(coverage: Pin<&mut Coverage>);
//         pub fn ClearCoverage(self: Pin<&mut TinyInstInstrumentation>);
//         // pub fn IgnoreCoverage(coverage: Pin<&mut Coverage>);

//     }
// }

#[cxx::bridge]
pub mod litecov {
    #[repr(u32)]
    enum RunResult {
        OK,
        CRASH,
        HANG,
        OTHER_ERROR,
    }

    #[repr(u32)]
    enum DebuggerStatus {
        DEBUGGER_NONE,
        DEBUGGER_CONTINUE,
        DEBUGGER_PROCESS_EXIT,
        DEBUGGER_TARGET_START,
        DEBUGGER_TARGET_END,
        DEBUGGER_CRASHED,
        DEBUGGER_HANGED,
        DEBUGGER_ATTACHED,
    }

    unsafe extern "C++" {
        include!("litecov.h");
        include!("coverage.h");
        // for constructors.
        include!("shim.h");
        include!("tinyinstinstrumentation.h");

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
        pub fn GetCoverage(
            self: Pin<&mut LiteCov>,
            coverage: Pin<&mut Coverage>,
            clear_coverage: bool,
        );
        pub fn IgnoreCoverage(self: Pin<&mut LiteCov>, coverage: Pin<&mut Coverage>);
        pub fn ClearCoverage(self: Pin<&mut LiteCov>);
        pub fn HasNewCoverage(self: Pin<&mut LiteCov>) -> bool;

        // class TinyInst
        pub fn EnableInstrumentation(self: Pin<&mut LiteCov>);
        pub fn DisableInstrumentation(self: Pin<&mut LiteCov>);

        type DebuggerStatus;
        // class Debugger
        // pub unsafe fn Run(self: Pin<&mut LiteCov>, cmd: *mut c_char, timeout: u32) -> DebuggerStatus;
        pub unsafe fn Run(
            self: Pin<&mut LiteCov>,
            argc: i32,
            argv: *mut *mut c_char,
            timeout: u32,
        ) -> DebuggerStatus;
        pub fn Kill(self: Pin<&mut LiteCov>) -> DebuggerStatus;
        pub fn Continue(self: Pin<&mut LiteCov>, timeout: u32) -> DebuggerStatus;
        pub fn Attach(self: Pin<&mut LiteCov>, pid: u32, timeout: u32) -> DebuggerStatus;

        pub fn IsTargetAlive(self: Pin<&mut LiteCov>) -> bool;
        pub fn IsTargetFunctionDefined(self: Pin<&mut LiteCov>) -> bool;
        pub fn GetTargetReturnValue(self: Pin<&mut LiteCov>) -> u64;
        pub unsafe fn get_coverage_map(
            bitmap: *mut u8,
            map_size: usize,
            coverage: Pin<&mut Coverage>,
        );

        // TinyinstInstrumentation
        type TinyInstInstrumentation;
        pub fn tinyinstinstrumentation_new() -> UniquePtr<TinyInstInstrumentation>;

        type RunResult;
        // type Coverage;
        pub unsafe fn Init(
            self: Pin<&mut TinyInstInstrumentation>,
            argc: i32,
            argv: *mut *mut c_char,
        );
        pub unsafe fn Run(
            self: Pin<&mut TinyInstInstrumentation>,
            argc: i32,
            argv: *mut *mut c_char,
            init_timeout: u32,
            timeout: u32,
        ) -> RunResult;

        pub unsafe fn RunWithCrashAnalysis(
            self: Pin<&mut TinyInstInstrumentation>,
            argc: i32,
            argv: *mut *mut c_char,
            init_timeout: u32,
            timeout: u32,
        ) -> RunResult;

        pub fn CleanTarget(self: Pin<&mut TinyInstInstrumentation>);
        pub fn HasNewCoverage(self: Pin<&mut TinyInstInstrumentation>) -> bool;

        pub fn GetCoverage(
            self: Pin<&mut TinyInstInstrumentation>,
            coverage: Pin<&mut Coverage>,
            clear_coverage: bool,
        );
        pub fn ClearCoverage(self: Pin<&mut TinyInstInstrumentation>);
        pub fn IgnoreCoverage(
            self: Pin<&mut TinyInstInstrumentation>,
            coverage: Pin<&mut Coverage>,
        );
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
