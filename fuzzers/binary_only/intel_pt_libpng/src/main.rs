#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{
        hooks::intel_pt::{IntelPTHook, SectionInfo},
        inprocess::GenericInProcessExecutor,
        ExitKind,
    },
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, HasLen};
use libpng_sys::ffi::{
    png_create_info_struct, png_create_read_struct, png_destroy_read_struct, png_process_data,
    png_set_crc_action, png_set_progressive_read_fn, png_set_user_limits, png_sig_cmp,
    PNG_CRC_QUIET_USE, PNG_LIBPNG_VER_STRING,
};
use proc_maps::get_process_maps;
use std::ffi::c_int;
use std::ptr::null_mut;
use std::{path::PathBuf, process, time::Duration};

// Coverage map
const MAP_SIZE: usize = 4096;
static mut MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];
#[allow(static_mut_refs)]
static mut MAP_PTR: *mut u8 = unsafe { MAP.as_mut_ptr() };

pub fn main() {
    // Enable logging
    env_logger::init();

    // The closure that we want to fuzz
    // heavily inspired by https://chromium.googlesource.com/chromium/src/+/refs/heads/main/testing/libfuzzer/fuzzers/libpng_read_fuzzer.cc
    let mut harness = |input: &BytesInput| {
        const PNG_HEADER_SIZE: usize = 8;

        if input.len() < PNG_HEADER_SIZE {
            return ExitKind::Ok;
        }

        if unsafe { png_sig_cmp(input.target_bytes().as_ptr(), 0, PNG_HEADER_SIZE) } != 0 {
            // not a PNG
            return ExitKind::Ok;
        }

        let mut png_ptr =
            unsafe { png_create_read_struct(PNG_LIBPNG_VER_STRING, null_mut(), None, None) };
        assert!(!png_ptr.is_null());

        unsafe {
            png_set_crc_action(
                &mut *png_ptr,
                PNG_CRC_QUIET_USE as c_int,
                PNG_CRC_QUIET_USE as c_int,
            )
        };

        let mut info_ptr = unsafe { png_create_info_struct(&mut *png_ptr) };
        assert!(!info_ptr.is_null());

        // setjmp?

        unsafe { png_set_progressive_read_fn(&mut *png_ptr, null_mut(), None, None, None) };
        let mut input_clone = input.target_bytes().to_vec();
        unsafe {
            png_process_data(
                &mut *png_ptr,
                &mut *info_ptr,
                input_clone.as_mut_ptr(),
                input.len(),
            )
        };

        if !info_ptr.is_null() {
            unsafe { png_destroy_read_struct(&raw mut png_ptr, &raw mut info_ptr, null_mut()) };
        } else {
            unsafe { png_destroy_read_struct(&raw mut png_ptr, null_mut(), null_mut()) };
        }

        ExitKind::Ok
    };

    // Create an observation channel using the map
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", MAP_PTR, MAP_SIZE) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions (crashes in this example),
        // on disk so the user can get them after stopping the fuzzer
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )
    .unwrap();

    // The Monitor trait define how the fuzzer stats are displayed to the user
    #[cfg(not(feature = "tui"))]
    let mon = SimpleMonitor::new(|s| println!("{s}"));
    #[cfg(feature = "tui")]
    let mon = TuiMonitor::builder()
        .title("Baby Fuzzer Intel PT")
        .enhanced_graphics(false)
        .build();

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Get the memory map of the current process
    let my_pid = i32::try_from(process::id()).unwrap();
    let process_maps = get_process_maps(my_pid).unwrap();
    let sections = process_maps
        .iter()
        .filter_map(|pm| {
            if pm.is_exec() && pm.filename().is_some() && pm.inode != 0 {
                Some(SectionInfo {
                    filename: pm.filename().unwrap().to_string_lossy().to_string(),
                    offset: pm.offset as u64,
                    size: pm.size() as u64,
                    virtual_address: pm.start() as u64,
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    println!("sections: {:?}", sections);

    // Intel PT hook that will handle the setup of Intel PT for each execution and fill the map
    let pt_hook = unsafe {
        IntelPTHook::builder()
            .map_ptr(MAP_PTR)
            .map_len(MAP_SIZE)
            .image(&sections)
    }
    .build();

    type PTInProcessExecutor<'a, EM, H, I, OT, S, T, Z> =
        GenericInProcessExecutor<EM, H, &'a mut H, (IntelPTHook<T>, ()), I, OT, S, Z>;
    // Create the executor for an in-process function with just one observer
    let mut executor = PTInProcessExecutor::with_timeout_generic(
        tuple_list!(pt_hook),
        &mut harness,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_millis(5000),
    )
    .expect("Failed to create the Executor");

    let seeds = PathBuf::from("./seeds");
    state
        .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seeds])
        .expect("Failed to generate the initial corpus");

    // Set up a mutational stage with a basic bytes mutator
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
