#[cfg(windows)]
use std::ptr::write_volatile;
use std::{marker::PhantomData, path::PathBuf, time::Duration};

#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list, AsMutSlice, AsSlice},
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::{Event, LogSeverity, SimpleEventManager},
    executors::{
        deferred::{ChannelExecutor, ChannelResult, ChannelTask},
        ExitKind,
    },
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    prelude::OwnedSliceMut,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
    HasRuntime,
};
use tokio::{sync::mpsc, time::sleep};

#[allow(clippy::similar_names)]
pub fn main() {
    // Create an observation channel using the signals map
    let observer = StdMapObserver::new_owned("signals", vec![0u8; 32]);

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
    let mon = SimpleMonitor::new(|s| println!("{}", s));
    #[cfg(feature = "tui")]
    let mon = TuiMonitor::new(String::from("Baby Fuzzer"), false);

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcasess from the corpus
    let scheduler = QueueScheduler::new();

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // sadly, rust cannot infer the type of these channels at this time
    let (tx_input, mut rx_input) = mpsc::channel::<ChannelTask<BytesInput>>(1);
    let (tx_result, rx_result) = mpsc::unbounded_channel();

    let handle = fuzzer.runtime().handle().clone();
    fuzzer.runtime().spawn(async move {
        let harness = |input: &BytesInput, signals: &mut OwnedSliceMut<u8>| {
            let mut signals_set = |idx: usize| {
                signals.as_mut_slice()[idx] = 1;
            };
            let target = input.target_bytes();
            let buf = target.as_slice();
            signals_set(0);
            if !buf.is_empty() && buf[0] == b'a' {
                signals_set(1);
                if buf.len() > 1 && buf[1] == b'b' {
                    signals_set(2);
                    if buf.len() > 2 && buf[2] == b'c' {
                        return ExitKind::Crash;
                    }
                }
            }
            ExitKind::Ok
        };
        while let Some(task) = rx_input.recv().await {
            let tx_result = tx_result.clone();
            let mut observer = observer.clone();
            handle.spawn(async move {
                // the executor is taking a nap :)
                sleep(Duration::from_secs(1)).await;
                tx_result
                    .send(ChannelResult::Event(Event::Log {
                        severity_level: LogSeverity::Info,
                        message: "Good morning!".to_string(),
                        phantom: PhantomData,
                    }))
                    .expect("Couldn't say good morning!");
                let exit_kind = (harness)(task.input(), observer.map_mut());
                tx_result.send(ChannelResult::Result {
                    task_id: task.task_id(),
                    result: Ok((exit_kind, tuple_list!(observer))),
                })
            });
        }
    });

    // Create the executor for an in-process function with just one observer
    let mut executor = ChannelExecutor::new(fuzzer.runtime(), tx_input, rx_result);

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::new(32);

    // Generate 8 initial inputs
    state
        .generate_initial_inputs_async(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("Failed to generate the initial corpus");

    // Setup a mutational stage with a basic bytes mutator
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new_async(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
