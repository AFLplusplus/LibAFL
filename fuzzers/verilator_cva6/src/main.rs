#![feature(array_windows)]
#![feature(concat_bytes)]

use std::{
    ffi::{c_char, c_int, CString},
    fs::File,
    io::{Seek, SeekFrom, Write},
    os::{fd::FromRawFd, unix::ffi::OsStrExt},
    time::Duration,
};

use libafl::{
    bolts::{current_nanos, AsSlice},
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{
        inprocess::TimeoutInProcessForkExecutor, ExitKind, InProcessExecutor, TimeoutExecutor,
    },
    feedback_or,
    feedbacks::{MaxMapFeedback, TimeFeedback},
    generators::RandBytesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimplePrintingMonitor,
    mutators::StdScheduledMutator,
    prelude::{
        havoc_mutations, tuple_list, ShMemProvider, StdRand, StdShMemProvider, TimeObserver,
    },
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler,
    },
    stages::{CalibrationStage, StdPowerMutationalStage},
    state::{HasCorpus, HasMaxSize, StdState},
    Error, Fuzzer, StdFuzzer,
};
use libafl_verilator::VerilatorMapObserver;
use nix::{fcntl::OFlag, sys::stat::Mode};

const BASE_EXECUTABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/base-executable"));

extern "C" {
    fn ariane_main(argc: c_int, argv: *const *const c_char) -> c_int;
}

fn main() -> Result<(), Error> {
    let mut mgr = SimpleEventManager::printing();

    let cov_observer = VerilatorMapObserver::new("verilated-edges".to_string());

    let time_observer = TimeObserver::new("time");

    let cov_feedback = MaxMapFeedback::new_tracking(&cov_observer, true, false);

    let calibration = CalibrationStage::new(&cov_feedback);

    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        cov_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new_with_observer(&time_observer)
    );

    let mut objective = (); // no feedback at this time :(

    let mut state = StdState::new(
        // RNG
        StdRand::with_seed(current_nanos()),
        // Corpus that will be evolved, we keep it in memory for performance
        InMemoryCorpus::new(),
        // Corpus in which we store solutions, but none are actually collected here
        InMemoryCorpus::new(),
        // States of the feedbacks.
        // The feedbacks can report the data that should persist in the State.
        &mut feedback,
        // Same for objective feedbacks
        &mut objective,
    )?;
    state.set_max_size(1 << 13); // see cva6-base.c for details

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let power = StdPowerMutationalStage::new(mutator, &cov_observer);

    let mut stages = tuple_list!(calibration, power);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
        PowerSchedule::FAST,
    ));

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let input_fd = nix::fcntl::open(
        "/tmp",
        OFlag::O_TMPFILE | OFlag::O_RDWR | OFlag::O_EXCL,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|errno| {
        Error::unknown(format!(
            "Couldn't create the temporary input file; got {:?}: {}",
            &errno,
            errno.desc()
        ))
    })?;
    let mut input_file = unsafe { File::from_raw_fd(input_fd) };
    let input_filename = CString::new(format!("/proc/self/fd/{}", input_fd)).unwrap();
    let jtag_setting = CString::new("+jtag_rbb_enable=0").unwrap();
    let executable_name = CString::new(std::env::current_exe()?.as_os_str().as_bytes()).unwrap();

    let cmd_args = [
        executable_name.as_ptr(),
        jtag_setting.as_ptr(),
        input_filename.as_ptr(),
    ];

    // at least 4 sequential c.nops
    let needle = Vec::from_iter(std::iter::repeat(1u16.to_le_bytes()).take(4).flatten());
    let nop_offset = BASE_EXECUTABLE
        .array_windows::<8>()
        .enumerate()
        .find_map(|(i, bytes)| if &needle == bytes { Some(i) } else { None })
        .unwrap();

    println!("offset: {}", nop_offset);

    // write the base executable
    input_file.write_all(BASE_EXECUTABLE).unwrap();

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();

        // for simplicity, we will write the input to the file
        // with customisation, we could hypothetically load this directly with DPI... but this is a PoC :)

        // write the assembly instructions into the perscribed needle
        input_file.seek(SeekFrom::Start(nop_offset as u64)).unwrap();
        input_file.write_all(buf).unwrap();
        input_file.seek(SeekFrom::Start(0)).unwrap();

        unsafe {
            ariane_main(cmd_args.len() as c_int, cmd_args.as_ptr());
        }

        ExitKind::Ok
    };

    let shmem = StdShMemProvider::new()?;

    let mut executor = TimeoutInProcessForkExecutor::new(
        &mut harness,
        tuple_list!(cov_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        Duration::from_secs(600),
        shmem,
    )?;

    if state.corpus().is_empty() {
        let mut generator = RandBytesGenerator::new(128);
        state.generate_initial_inputs(
            &mut fuzzer,
            &mut executor,
            &mut generator,
            &mut mgr,
            1 << 6,
        )?;
        println!("Generated {} initial inputs", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

    Ok(())
}
