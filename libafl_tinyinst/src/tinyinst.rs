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
mod litecov {
    unsafe extern "C++"{
        include!("litecov.h");
        include!("common.h");

        type ModuleCovData;
        type LiteCov;
        type ModuleInfo;

        pub fn HasNewCoverage(self: Pin<&mut LiteCov>) -> bool;
        pub fn ClearInstrumentationData(self: Pin<&mut ModuleCovData>);
        pub unsafe fn Init(self: Pin<&mut LiteCov>, argc: i32, argv: *mut *mut c_char);
    }
}