use std::{
    env,
    ffi::{CStr, CString},
    num::NonZero,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    time::Duration,
};

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{
        command::CommandConfigurator,
        hooks::intel_pt::{IntelPTHook, Section},
    },
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasMutatorBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations::havoc_mutations, scheduled::StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{core_affinity, intel_pt::IntelPT, rands::StdRand, tuples::tuple_list, Error};
use nix::{
    sys::{
        ptrace::traceme,
        signal::{raise, Signal},
    },
    unistd::{execv, fork, ForkResult, Pid},
};

// Coverage map
const MAP_SIZE: usize = 4096;
static mut MAP: [u8; MAP_SIZE] = [0; MAP_SIZE];
#[allow(static_mut_refs)]
static mut MAP_PTR: *mut u8 = unsafe { MAP.as_mut_ptr() };

pub fn main() {
    // Let's set the default logging level to `warn`
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "warn")
    }
    // Enable logging
    env_logger::init();

    // Create an observation channel using the signals map
    let observer = unsafe { StdMapObserver::from_mut_ptr("signals", MAP_PTR, MAP_SIZE) };

    // Feedback to rate the interestingness of an input, obtained by ANDing the interestingness of both feedbacks
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = StdState::new(
        // RNG
        StdRand::new(),
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
    let mon = SimpleMonitor::new(|s| println!("{s}"));

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut intel_pt = IntelPT::builder().cpu(0).inherit(true).build().unwrap();
    intel_pt.set_ip_filters(&[0x21_0000..=0x25_0000]).unwrap();
    let executable = PathBuf::from(env::args().next().unwrap())
        .parent()
        .unwrap()
        .join("target_program")
        .to_string_lossy()
        .to_string();
    let sections = [Section {
        file_path: executable,
        file_offset: 0xf0a0,
        size: 0x40000,
        virtual_address: 0x2100a0,
    }];

    let hook = unsafe { IntelPTHook::builder().map_ptr(MAP_PTR).map_len(MAP_SIZE) }
        .intel_pt(intel_pt)
        .image(&sections)
        .build();

    #[derive(Debug)]
    pub struct MyCommandConfigurator {}

    impl CommandConfigurator<BytesInput, Pid> for MyCommandConfigurator {
        fn spawn_child(&mut self, input: &BytesInput) -> Result<Pid, Error> {
            // TODO move to new
            let executable = PathBuf::from(env::args().next().unwrap())
                .parent()
                .unwrap()
                .join("target_program")
                .into_os_string();
            let input = [input.bytes(), &[b'\0']].concat();
            let arg1 = CStr::from_bytes_until_nul(&input).unwrap();

            let child = match unsafe { fork() } {
                Ok(ForkResult::Parent { child }) => child,
                Ok(ForkResult::Child) => {
                    traceme().unwrap();
                    let cores = core_affinity::get_core_ids().unwrap();
                    cores[0].set_affinity().unwrap();
                    raise(Signal::SIGSTOP).expect("Failed to stop the process");

                    execv(&CString::new(executable.as_bytes()).unwrap(), &[arg1]).unwrap();

                    unreachable!("execv returns only on error and its result is unwrapped");
                }
                Err(e) => panic!("Fork failed {e}"),
            };

            Ok(child)
        }

        fn exec_timeout(&self) -> Duration {
            Duration::from_secs(2)
        }

        fn exec_timeout_mut(&mut self) -> &mut Duration {
            todo!()
        }
    }

    let command_configurator = MyCommandConfigurator {};
    let mut executor =
        command_configurator.into_executor_with_hooks(tuple_list!(observer), tuple_list!(hook));

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(NonZero::new(32).unwrap());

    // Generate 8 initial inputs
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
