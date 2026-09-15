use std::{marker::PhantomData, path::PathBuf, ptr::write};
#[cfg(feature = "tui")]
use libafl::monitors::tui::TuiMonitor;
#[cfg(not(feature = "tui"))]
use libafl::monitors::SimpleMonitor;
use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{Executor, ExitKind, WithObservers},
    feedback_and_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::StdFuzzer,
    generators::RandPrintablesGenerator,
    inputs::HasTargetBytes,
    mutators::{havoc_mutations::havoc_mutations, scheduled::HavocScheduledMutator},
    observers::ConstMapObserver,
    schedulers::QueueScheduler,
    stages::{CalibrationStage, StdMutationalStage},
    state::{HasExecutions, StdState},
};
use libafl_bolts::{current_nanos, nonnull_raw_mut, nonzero, rands::StdRand, tuples::tuple_list};
/// Coverage map with explicit assignments due to the lack of instrumentation
const SIGNALS_LEN: usize = 16;
static mut SIGNALS: [u8; SIGNALS_LEN] = [0; SIGNALS_LEN];
static mut SIGNALS_PTR: *mut u8 = &raw mut SIGNALS as _;

/// Assign a signal to the signals map
fn signals_set(idx: usize) {
    unsafe { write(SIGNALS_PTR.add(idx), 1) };
}

struct CustomExecutor<S> {
    phantom: PhantomData<S>,
}

impl<S> CustomExecutor<S> {
    pub fn new(_state: &S) -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<EM, I, S, Z> Executor<EM, I, S, Z> for CustomExecutor<S>
where
    I: HasTargetBytes,
    S: HasExecutions,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, libafl_bolts::Error> {
        *state.executions_mut() += 1;

        let target = input.target_bytes();
        let buf = &target;
        signals_set(0);
        if !buf.is_empty() && buf[0] == b'a' {
            signals_set(1);
            if buf.len() > 1 && buf[1] == b'b' {
                signals_set(2);
                if buf.len() > 2 && buf[2] == b'c' {
                    return Ok(ExitKind::Crash);
                }
            }
        }
        Ok(ExitKind::Ok)
    }
}

pub fn main() {
    // Create an observation channel using the signals map
    let observer = unsafe { ConstMapObserver::from_mut_ptr("signals", nonnull_raw_mut!(SIGNALS)) };

    // Feedback to rate the interestingness of an input
    let mut feedback = MaxMapFeedback::new(&observer);

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_and_fast!(
        // Look for crashes.
        CrashFeedback::new(),
        // We `and` the MaxMapFeedback to only end up with crashes that trigger new coverage.
        // We use the _fast variant to make sure it's not evaluated every time, even if the crash didn't trigger..
        // We have to give this one a name since it differs from the first map.
        MaxMapFeedback::with_name("on_crash", &observer)
    );

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
        .title("Baby Fuzzer")
        .enhanced_graphics(false)
        .build();

    // The event manager handle the various events generated during the fuzzing loop
    // such as the notification of the addition of a new item to the corpus
    let mut mgr = SimpleEventManager::new(mon);

    // A queue policy to get testcases from the corpus
    let scheduler = QueueScheduler::new();

    // Setup stages
    let calibration_stage = CalibrationStage::new();
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mutational_stage = StdMutationalStage::new(mutator);
    let stages = tuple_list!(calibration_stage, mutational_stage);

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective, stages);

    // Create the executor with observer
    let executor = CustomExecutor::new(&state);
    let mut with_obs = WithObservers::new(executor, tuple_list!(observer));

    // Generator of printable bytearrays of max size 32
    let mut generator = RandPrintablesGenerator::with_min_size(nonzero!(1), nonzero!(32));

    // Generate 8 initial inputs
    fuzzer
        .generate_initial_inputs_with_executor(
            &mut with_obs,
            &mut generator,
            &mut state,
            &mut mgr,
            8,
        )
        .expect("Failed to generate the initial corpus");

    fuzzer
        .fuzz_loop(&mut with_obs, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
