#![cfg(feature = "std")]
#![cfg(target_os = "windows")]

use std::{ffi::c_void, fs::File, io::Write};

use libafl_intelpt::{IntelPT, availability};
use windows::Win32::{
    Foundation::{CloseHandle, WAIT_OBJECT_0},
    System::Threading::{
        CreateThread, GetThreadId, INFINITE, Sleep, THREAD_CREATION_FLAGS, WaitForSingleObject,
    },
};

extern "system" fn worker_main(_lp_parameter: *mut c_void) -> u32 {
    unsafe { Sleep(2000) };
    0
}

#[test]
fn intel_pt_trace_thread() {
    if let Err(reason) = availability() {
        println!("Intel PT is not available, skipping test. Reasons:");
        println!("{reason}");
        return;
    }

    let thread_handle = unsafe {
        CreateThread(
            None,
            0,
            Some(worker_main),
            Some(std::ptr::null_mut()),
            THREAD_CREATION_FLAGS(0),
            None,
        )
    }
    .expect("Failed to create worker thread");

    let thread_id = unsafe { GetThreadId(thread_handle) };
    assert!(
        thread_id != 0,
        "Failed to read worker thread ID from parent"
    );

    let mut pt = IntelPT::builder()
        .thread_id(thread_id)
        .images(&[])
        .build()
        .expect("Failed to create IntelPT for worker thread");
    pt.enable_tracing().expect("Failed to enable tracing");

    let wait_result = unsafe { WaitForSingleObject(thread_handle, INFINITE) };
    assert_eq!(
        wait_result, WAIT_OBJECT_0,
        "Worker thread did not terminate cleanly"
    );

    let trace = pt
        .get_raw_trace()
        .expect("Failed to get raw trace from raw trace");

    let mut file = File::create("output.bin").unwrap();
    file.write_all(&trace).unwrap();

    let _ = unsafe { CloseHandle(thread_handle) };
}
