#![cfg(feature = "std")]
#![cfg(target_os = "windows")]

use std::{
    arch::asm,
    process, slice,
    sync::{
        Arc, Barrier,
        mpsc::{Sender, channel},
    },
    thread,
};

use libafl_intelpt::{IntelPT, availability};
use log::LevelFilter;
use proc_maps::get_process_maps;
use ptcov::PtImage;
use windows::Win32::System::Threading::GetCurrentThreadId;

fn worker_main(thread_id_sender: Sender<u32>, barrier: Arc<Barrier>) -> u32 {
    let tid = unsafe { GetCurrentThreadId() };
    thread_id_sender.send(tid).unwrap();

    barrier.wait();

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

    barrier.wait();
    count
}

#[test]
fn intel_pt_trace_thread() {
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

    let (thread_id_sender, thread_id_receiver) = channel();
    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = barrier.clone();
    let worker = thread::spawn(|| worker_main(thread_id_sender, worker_barrier));
    let worker_tid = thread_id_receiver.recv().unwrap();
    pt.set_tid(Some(worker_tid));
    pt.enable_tracing().unwrap();
    barrier.wait();

    let mut map = vec![0u16; 0x10_00];
    pt.decode_traces_into_map(map.as_mut_ptr(), map.len())
        .unwrap();

    let assembly_jump_id = map.iter().position(|count| *count >= 254);
    assert!(
        assembly_jump_id.is_some(),
        "Assembly jumps not found in traces"
    );

    barrier.wait();
    worker.join().expect("Worker thread panicked");
}
