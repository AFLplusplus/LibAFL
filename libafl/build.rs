//! special handling to build and link libafl

use rustc_version::{version_meta, Channel};

#[allow(clippy::ptr_arg, clippy::upper_case_acronyms)]
fn main() {
    #[cfg(target_os = "windows")]
    #[allow(clippy::ptr_arg, clippy::upper_case_acronyms)]
    windows::build!(
        Windows::Win32::Foundation::{HANDLE, HWND, BOOL, PSTR, CloseHandle, NTSTATUS},
        Windows::Win32::System::{
            Memory::{CreateFileMappingA, OpenFileMappingA, MapViewOfFile, UnmapViewOfFile, FILE_MAP, PAGE_TYPE},
            Diagnostics::Debug::{SetUnhandledExceptionFilter, EXCEPTION_POINTERS, EXCEPTION_RECORD, LPTOP_LEVEL_EXCEPTION_FILTER},
            Threading::{CreateTimerQueue, CreateTimerQueueTimer, DeleteTimerQueueTimer, ExitProcess},
        },
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
