//! A singlethreaded QEMU fuzzer that can auto-restart.
use core::time::Duration;
use std::path::PathBuf;

use std::mem::MaybeUninit;

use libafl::bolts::AsSlice;
use libafl::corpus::PowerQueueCorpusScheduler;
use libafl::mutators::StdMOptMutator;
use libafl::stages::power::PowerSchedule;
use libafl::stages::CalibrationStage;
use libafl::stages::PowerMutationalStage;
use libafl_qemu_fullsystem::libafl_disable_edge_gen;
use libafl_qemu_fullsystem::libafl_enable_edge_gen;
use libafl_qemu_fullsystem::Emulator;
use libafl_qemu_fullsystem::QemuCmpLogHelper;
use libafl_qemu_fullsystem::QemuEdgeCoverageHelper;
use libafl_qemu_fullsystem::QemuHooks;

use libc::c_void;

use klo_routines::*;

use libafl_qemu_fullsystem::cmplog::CmpLogObserver;

use libafl::{
    bolts::{
        current_nanos,
        rands::StdRand,
        serdeany::RegistryBuilder,
        tuples::{tuple_list, Merge},
    },
    corpus::{Corpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus},
    executors::{ExitKind, ShadowExecutor, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{scheduled::havoc_mutations, tokens_mutations, I2SRandReplace, Tokens},
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    stages::{ShadowTracingStage, StdMutationalStage},
    state::{HasCorpus, StdState},
};
use libafl_qemu_fullsystem::QemuExecutor;

use libafl::state::HasMaxSize;

use libafl_qemu_fullsystem::cmplog;
use libafl_qemu_fullsystem::edges;
use libafl_qemu_fullsystem::SimpleQemuRestartingEventManager;

fn input_generator() {
    // The closure that produced the input for the generator
    let mut harness = |input: &BytesInput| {
        {
            let mut ex = EXIT_KIND.lock().unwrap();
            *ex = ExitKind::Ok;
        }
        // The `yield_` switches execution context back to the loop in `main`.
        // When `resume` is called, we return to this function.
        yield_(input);
        // get work called()
        // optee executes our test case
        //println!("EXITKIND: {:?}", unsafe {EXIT_KIND.clone()});
        // check result
        let ex = EXIT_KIND.lock().unwrap();

        *ex
    };

    // Create an observation channel using the coverage map
    let edges = unsafe { &mut edges::EDGES_MAP };
    let edges_counter = unsafe { &mut edges::MAX_EDGES_NUM };
    let edges_observer =
        HitcountsMapObserver::new(VariableMapObserver::new("edges", edges, edges_counter));

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Create an observation channel using cmplog map
    let cmplog_observer = CmpLogObserver::new("cmplog", unsafe { &mut cmplog::CMPLOG_MAP }, true);

    // The state of the edges feedback.
    let feedback_state = MapFeedbackState::with_observer(&edges_observer);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new_with_observer(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    let monitor = SimpleMonitor::new(|s| {
        println!("{}", s);
    });
    let state = None;

    let crashes_dir = PathBuf::from("./crashes");

    // create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            //InMemoryCorpus::new(),
            OnDiskCorpus::new(PathBuf::from("./corpus")).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(crashes_dir.clone()).unwrap(),
            // States of the feedbacks.
            // They are the data related to the feedbacks that you want to persist in the State.
            tuple_list!(feedback_state),
        )
    });

    state.set_max_size(4_096);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    //let mut mgr = SimpleEventManager::new(stats);
    let mut mgr = SimpleQemuRestartingEventManager::new(monitor);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(PowerQueueCorpusScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let emu = Emulator::new_empty();

    let hooks = QemuHooks::new(
        &emu,
        tuple_list!(
            QemuEdgeCoverageHelper::default(),
            QemuCmpLogHelper::default(),
        ),
    );

    let calibration = CalibrationStage::new(&mut state, &edges_observer);

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdMOptMutator::new(&mut state, havoc_mutations().merge(tokens_mutations()), 5)
        .expect("could not initalize MOpt");

    let power = PowerMutationalStage::new(mutator, PowerSchedule::FAST, &edges_observer);

    let executor = QemuExecutor::new(
        hooks,
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let timeout = Duration::from_millis(60_000);
    let executor = TimeoutExecutor::new(executor, timeout);
    // // // Show the cmplog observer
    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    // Generator of printable bytearrays of max size 32
    //let mut generator = RandBytesGenerator::new(4096);

    let tracing = ShadowTracingStage::new(&mut executor);

    // Setup a randomic Input2State stage
    let i2s = StdMutationalStage::new(I2SRandReplace::new());

    let mut stages = tuple_list!(calibration, tracing, i2s, power);

    let seed_dir = PathBuf::from("./seeds");

    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut mgr,
                &[crashes_dir, seed_dir.clone()],
            )
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}

static mut KLO: MaybeUninit<klo_routines::KloRoutine<'static, fn(), &BytesInput>> =
    MaybeUninit::uninit();
static mut INPUT_GEN: fn() = input_generator;

use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref EXIT_KIND: Mutex<ExitKind> = Mutex::new(ExitKind::Ok);
}

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub extern "C" fn libafl_init_fuzzer() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    RegistryBuilder::register::<Tokens>();

    println!("got hypercall (Rusty side)");

    // unsafe {
    //     INPUT_MAP_ADDR = input_map_addr;
    //     INPUT_MAP_SIZE = input_map_size;
    // }

    unsafe {
        let klo = KloRoutine::<_, &'static BytesInput>::with_stack_size(
            &mut INPUT_GEN,
            512 * 1024 * 1024,
        );
        KLO.write(klo);
    }
}

#[no_mangle]
fn libafl_finishwork() {
    let mut ex = EXIT_KIND.lock().unwrap();
    *ex = ExitKind::Ok;
}

#[no_mangle]
fn libafl_crash() {
    let mut ex = EXIT_KIND.lock().unwrap();
    *ex = ExitKind::Crash;
}

#[no_mangle]
fn libafl_restore() {
    let mut ex = EXIT_KIND.lock().unwrap();
    *ex = ExitKind::Crash;
}

#[no_mangle]
fn libafl_user_crash() {
    libafl_disable_edge_gen();
}

/// The actual fuzzer
#[no_mangle]
fn libafl_getwork(input_map_qemu: *const c_void, input_map_qemu_sz: u64) {
    //println!("Hello from fuzz()");

    libafl_enable_edge_gen();

    let klo = unsafe { KLO.assume_init_mut() };

    if let Some(input) = klo.resume() {
        //println!("got input: {:?}", input);
        let in_map_slice = unsafe {
            std::slice::from_raw_parts_mut(input_map_qemu as *mut u8, input_map_qemu_sz as usize)
        };
        let target = input.target_bytes();
        let buf = target.as_slice();
        let sz = core::cmp::min(buf.len(), in_map_slice.len() - 2);

        // encode buffer size (16 bit) in first two bytes
        in_map_slice[0] = ((sz as u16) & 0xFF) as u8;
        in_map_slice[1] = (((sz as u16) >> 8) & 0xFF) as u8;

        in_map_slice[2..sz + 2].copy_from_slice(&buf[0..sz]);
        //unsafe { cpu_memory_rw_debug(cpu, INPUT_MAP_ADDR, buf.as_ptr() as *const c_void, sz as u64, true); }
        // place slice at INPUT_MAP_ADDR
        // reset exitkind
        let mut ex = EXIT_KIND.lock().unwrap();
        *ex = ExitKind::Ok;
    }
}
