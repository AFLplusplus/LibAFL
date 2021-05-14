//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use libafl::{
    bolts::tuples::tuple_list,
    corpus::{
        ondisk::OnDiskMetadataFormat, Corpus, InMemoryCorpus,
        IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus, QueueCorpusScheduler,
    },
    events::setup_restarting_mgr_std,
    executors::{
        inprocess::InProcessExecutor, timeout::TimeoutExecutor, Executor, ExitKind, HasExecHooks,
        HasExecHooksTuple, HasObservers, HasObserversHooks,
    },
    feedback_or,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{HasTargetBytes, Input},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    mutators::token_mutations::Tokens,
    observers::{HitcountsMapObserver, ObserversTuple, StdMapObserver, TimeObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
    Error,
};

use frida_gum::{
    stalker::{NoneEventSink, Stalker},
    Gum, NativePointer,
};

use std::{env, ffi::c_void, marker::PhantomData, path::PathBuf, time::Duration};

use libafl_frida::{
    asan_rt::{AsanErrorsFeedback, AsanErrorsObserver, ASAN_ERRORS},
    helper::{FridaHelper, FridaInstrumentationHelper, MAP_SIZE},
    FridaOptions,
};

struct FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    base: TimeoutExecutor<InProcessExecutor<'a, H, I, OT, S>, I>,
    /// Frida's dynamic rewriting engine
    stalker: Stalker<'a>,
    /// User provided callback for instrumentation
    helper: &'c mut FH,
    followed: bool,
    _phantom: PhantomData<&'b u8>,
}

impl<'a, 'b, 'c, FH, H, I, OT, S> Executor<I>
    for FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// Instruct the target about the input and run
    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        if self.helper.stalker_enabled() {
            if !self.followed {
                self.followed = true;
                self.stalker
                    .follow_me::<NoneEventSink>(self.helper.transformer(), None);
            } else {
                self.stalker.activate(NativePointer(
                    self.base.inner().harness_mut() as *mut _ as *mut c_void
                ))
            }
        }
        let res = self.base.run_target(input);
        if unsafe { ASAN_ERRORS.is_some() && !ASAN_ERRORS.as_ref().unwrap().is_empty() } {
            println!("Crashing target as it had ASAN errors");
            unsafe {
                libc::raise(libc::SIGABRT);
            }
        }
        if self.helper.stalker_enabled() {
            self.stalker.deactivate();
        }
        res
    }
}

impl<'a, 'b, 'c, EM, FH, H, I, OT, S, Z> HasExecHooks<EM, I, S, Z>
    for FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// Called right before exexution starts
    #[inline]
    fn pre_exec(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        self.helper.pre_exec(input);
        self.base.pre_exec(fuzzer, state, event_mgr, input)
    }

    /// Called right after execution finished.
    #[inline]
    fn post_exec(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<(), Error> {
        self.helper.post_exec(input);
        self.base.post_exec(fuzzer, state, event_mgr, input)
    }
}

impl<'a, 'b, 'c, FH, H, I, OT, S> HasObservers<OT>
    for FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn observers(&self) -> &OT {
        self.base.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        self.base.observers_mut()
    }
}

impl<'a, 'b, 'c, EM, FH, H, I, OT, S, Z> HasObserversHooks<EM, I, OT, S, Z>
    for FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}

impl<'a, 'b, 'c, FH, H, I, OT, S> FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(
        gum: &'a Gum,
        base: InProcessExecutor<'a, H, I, OT, S>,
        helper: &'c mut FH,
        timeout: Duration,
    ) -> Self {
        let stalker = Stalker::new(gum);

        // Let's exclude the main module and libc.so at least:
        //stalker.exclude(&MemoryRange::new(
        //Module::find_base_address(&env::args().next().unwrap()),
        //get_module_size(&env::args().next().unwrap()),
        //));
        //stalker.exclude(&MemoryRange::new(
        //Module::find_base_address("libc.so"),
        //get_module_size("libc.so"),
        //));

        Self {
            base: TimeoutExecutor::new(base, timeout),
            stalker,
            helper,
            followed: false,
            _phantom: PhantomData,
        }
    }
}

/// The main fn, usually parsing parameters, and starting the fuzzer
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    color_backtrace::install();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    unsafe {
        fuzz(
            &env::args().nth(1).expect("no module specified"),
            &env::args().nth(2).expect("no symbol specified"),
            env::args()
                .nth(3)
                .expect("no modules to instrument specified")
                .split(':')
                .map(|module_name| std::fs::canonicalize(module_name).unwrap())
                .collect(),
            &vec![PathBuf::from("./corpus")],
            PathBuf::from("./crashes"),
            1337,
        )
        .expect("An error occurred while fuzzing");
    }
}

/// Not supported on windows right now
#[cfg(windows)]
fn fuzz(
    _module_name: &str,
    _symbol_name: &str,
    _corpus_dirs: Vec<PathBuf>,
    _objective_dir: PathBuf,
    _broker_port: u16,
) -> Result<(), ()> {
    todo!("Example not supported on Windows");
}

/// The actual fuzzer
#[cfg(unix)]
unsafe fn fuzz(
    module_name: &str,
    symbol_name: &str,
    modules_to_instrument: Vec<PathBuf>,
    corpus_dirs: &Vec<PathBuf>,
    objective_dir: PathBuf,
    broker_port: u16,
) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) = match setup_restarting_mgr_std(stats, broker_port) {
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {}", err);
            }
        },
    };

    let gum = Gum::obtain();

    let lib = libloading::Library::new(module_name).unwrap();
    let target_func: libloading::Symbol<unsafe extern "C" fn(data: *const u8, size: usize) -> i32> =
        lib.get(symbol_name.as_bytes()).unwrap();

    let mut frida_harness = move |buf: &[u8]| {
        (target_func)(buf.as_ptr(), buf.len());
        ExitKind::Ok
    };

    let frida_options = FridaOptions::parse_env_options();
    let mut frida_helper =
        FridaInstrumentationHelper::new(&gum, &frida_options, module_name, &modules_to_instrument);

    // Create an observation channel using the coverage map
    let edges_observer = HitcountsMapObserver::new(StdMapObserver::new_from_ptr(
        "edges",
        frida_helper.map_ptr(),
        MAP_SIZE,
    ));

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Create an observation channel for ASan violations
    let asan_observer = AsanErrorsObserver::new(&ASAN_ERRORS);

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

    // Feedbacks to recognize an input as solution
    let objective = feedback_or!(
        CrashFeedback::new(),
        TimeoutFeedback::new(),
        AsanErrorsFeedback::new()
    );

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new_save_meta(objective_dir, Some(OnDiskMetadataFormat::JsonPretty))
                .unwrap(),
            // States of the feedbacks.
            // They are the data related to the feedbacks that you want to persist in the State.
            tuple_list!(feedback_state),
        )
    });

    println!("We're a client, let's fuzz :)");

    // Create a PNG dictionary if not existing
    if state.metadata().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::new(vec![
            vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header
            b"IHDR".to_vec(),
            b"IDAT".to_vec(),
            b"PLTE".to_vec(),
            b"IEND".to_vec(),
        ]));
    }

    // Setup a basic mutator with a mutational stage
    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    frida_helper.register_thread();

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = FridaInProcessExecutor::new(
        &gum,
        InProcessExecutor::new(
            &mut frida_harness,
            tuple_list!(edges_observer, time_observer, asan_observer),
            &mut fuzzer,
            &mut state,
            &mut restarting_mgr,
        )?,
        &mut frida_helper,
        Duration::new(10, 0),
    );
    // Let's exclude the main module and libc.so at least:
    //executor.stalker.exclude(&MemoryRange::new(
    //Module::find_base_address(&env::args().next().unwrap()),
    //get_module_size(&env::args().next().unwrap()),
    //));
    //executor.stalker.exclude(&MemoryRange::new(
    //Module::find_base_address("libc.so"),
    //get_module_size("libc.so"),
    //));

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(
                &mut fuzzer,
                &mut executor,
                &mut restarting_mgr,
                &corpus_dirs,
            )
            .expect(&format!(
                "Failed to load initial corpus at {:?}",
                &corpus_dirs
            ));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;

    // Never reached
    Ok(())
}
