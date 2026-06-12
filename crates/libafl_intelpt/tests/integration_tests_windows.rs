#![cfg(feature = "std")]
#![cfg(target_os = "windows")]

extern crate alloc;

use std::{arch::asm, process};
use alloc::slice;

use libafl_intelpt::{IntelPT, availability};
use log::LevelFilter;
use proc_maps::get_process_maps;
use ptcov::PtImage;
use windows::Win32::System::Threading::GetCurrentThreadId;

#[test]
fn intel_pt_trace_loop() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(LevelFilter::Trace)
        .try_init();

    if let Err(reason) = availability() {
        println!("Intel PT is not available, skipping test. Reasons:");
        println!("{reason}");
        return;
    }

    let pid = process::id();

    let maps = get_process_maps(pid).expect("failed to get process maps");
    let images = maps
        .iter()
        .filter(|map| map.is_exec())
        .map(|pm| {
            let data = unsafe { slice::from_raw_parts(pm.start() as *const u8, pm.size()) };
            PtImage::new(data, pm.start() as u64)
        })
        .collect::<Vec<_>>();

    let mut pt = IntelPT::builder()
        .images(&images)
        .build()
        .expect("Failed to create IntelPT for worker thread");
    let tid = unsafe { GetCurrentThreadId() };
    pt.set_thread_id(Some(tid));
    pt.enable_tracing().unwrap();

    let mut count = 0;
    unsafe {
        asm!(
        "2:",
        "add {0:r}, 1",
        "cmp {0:r}, 255",
        "jle 2b",
        inout(reg) count,
        options(nostack)
        );
    }
    let _ = count;

    pt.disable_tracing().unwrap();

    let mut map = vec![0u16; 0x10_00];
    pt.decode_traces_into_map(map.as_mut_ptr(), map.len())
        .unwrap();

    let assembly_jump_id = map.iter().position(|count| *count >= 254);
    assert!(
        assembly_jump_id.is_some(),
        "Assembly jumps not found in traces"
    );
}
