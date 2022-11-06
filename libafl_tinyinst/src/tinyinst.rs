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
    enum RunResult {
        OK,
        CRASH,
        HANG,
        OTHER_ERROR,
    }

    unsafe extern "C++" {
        include!("coverage.h");
        // for constructors.
        include!("shim.h");
        include!("tinyinstinstrumentation.h");
        include!("aflcov.h");

        type ModuleCovData;
        pub fn ClearInstrumentationData(self: Pin<&mut ModuleCovData>);
        pub fn ClearCmpCoverageData(self: Pin<&mut ModuleCovData>);

        type Coverage;
        type ModuleCoverage;

        pub fn coverage_new() -> UniquePtr<Coverage>;

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

        // Testing AFLCOV
        type AFLCov;
        pub unsafe fn aflcov_new(coverage: *mut u8, capacity: usize) -> UniquePtr<AFLCov>;
        pub fn add_coverage(self: Pin<&mut AFLCov>, addr: u64);
    }
}

use cxx::UniquePtr;
impl litecov::TinyInstInstrumentation {
    pub fn new() -> UniquePtr<litecov::TinyInstInstrumentation> {
        litecov::tinyinstinstrumentation_new()
    }
}

impl litecov::Coverage {
    pub fn new() -> UniquePtr<litecov::Coverage> {
        litecov::coverage_new()
    }
}

impl litecov::AFLCov {
    pub unsafe fn new(coverage: *mut u8, capacity: usize) -> UniquePtr<litecov::AFLCov> {
        litecov::aflcov_new(coverage, capacity)
    }
}
