use std::ffi::c_int;

use libafl::{
    events::{ProgressReporter, SimpleEventManager},
    executors::HasObservers,
    feedbacks::{MapFeedbackMetadata, MAPFEEDBACK_PREFIX},
    inputs::UsesInput,
    monitors::SimpleMonitor,
    stages::StagesTuple,
    state::{HasClientPerfMonitor, HasExecutions, HasMetadata, HasNamedMetadata},
    Error, Fuzzer,
};

use crate::{fuzz_with, options::LibfuzzerOptions};

fn do_report<F, ST, E, S, EM>(
    _options: &LibfuzzerOptions,
    _fuzzer: &mut F,
    _stages: &mut ST,
    _executor: &mut E,
    state: &mut S,
    _mgr: &mut EM,
) -> Result<(), Error>
where
    F: Fuzzer<E, EM, ST, State = S>,
    S: HasClientPerfMonitor + HasMetadata + HasNamedMetadata + HasExecutions + UsesInput,
    E: HasObservers<State = S>,
    EM: ProgressReporter<State = S>,
    ST: StagesTuple<E, EM, S, F>,
{
    let meta = state
        .named_metadata()
        .get::<MapFeedbackMetadata<u8>>(&(MAPFEEDBACK_PREFIX.to_string() + "edges"))
        .unwrap();
    let observed = meta.history_map.iter().filter(|&&e| e != 0).count();
    let total = meta.history_map.len();

    println!(
        "Observed {observed}/{total} edges ({}%)",
        observed as f64 / total as f64
    );

    Ok(())
}

pub fn report(
    options: LibfuzzerOptions,
    harness: &extern "C" fn(*const u8, usize) -> c_int,
) -> Result<(), Error> {
    fuzz_with!(options, harness, do_report, |reporter| {
        let mgr = SimpleEventManager::new(SimpleMonitor::new(|s| eprintln!("{s}")));
        crate::start_fuzzing_single(reporter, None, mgr)
    })
}
