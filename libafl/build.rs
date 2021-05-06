//! special handling to build and link libafl

use rustc_version::{version_meta, Channel};

fn main() {
    #[cfg(target_os = "windows")]
    windows::build!(
        windows::win32::system_services::{HANDLE, BOOL, PAGE_TYPE, PSTR, ExitProcess},
        windows::win32::windows_programming::CloseHandle,
        // API needed for the shared memory
        windows::win32::system_services::{CreateFileMappingA, OpenFileMappingA, MapViewOfFile, UnmapViewOfFile},
        windows::win32::debug::{SetUnhandledExceptionFilter, EXCEPTION_POINTERS, EXCEPTION_RECORD, LPTOP_LEVEL_EXCEPTION_FILTER}
    );

    // Set cfg flags depending on release channel
    match version_meta().unwrap().channel {
        Channel::Stable => {
            println!("cargo:rustc-cfg=RUSTC_IS_STABLE");
        }
        Channel::Beta => {
            println!("cargo:rustc-cfg=RUSTC_IS_BETA");
        }
        Channel::Nightly => {
            println!("cargo:rustc-cfg=RUSTC_IS_NIGHTLY");
        }
        Channel::Dev => {
            println!("cargo:rustc-cfg=RUSTC_IS_DEV");
        }
    }
}
