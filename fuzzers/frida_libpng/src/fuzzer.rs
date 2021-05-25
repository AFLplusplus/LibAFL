//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use clap::{App, Arg};

#[cfg(target_os = "android")]
use libafl::bolts::os::ashmem_server::AshmemService;

use libafl::{
    bolts::{
        current_nanos,
        launcher::Launcher,
        os::parse_core_bind_arg,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
    },
    corpus::{
        ondisk::OnDiskMetadataFormat, Corpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    executors::{
        inprocess::InProcessExecutor, timeout::TimeoutExecutor, Executor, ExitKind,
        HasExecHooksTuple, HasObservers, HasObserversHooks,
    },
    feedback_or,
    feedbacks::{CrashFeedback, MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes, Input},
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        token_mutations::Tokens,
    },
    observers::{HitcountsMapObserver, ObserversTuple, StdMapObserver, TimeObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, StdState},
    stats::MultiStats,
    Error,
};

use frida_gum::{
    stalker::{NoneEventSink, Stalker},
    Gum, MemoryRange, NativePointer,
};

use std::{
    env,
    ffi::c_void,
    marker::PhantomData,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use libafl_frida::{
    asan_errors::{AsanErrorsFeedback, AsanErrorsObserver, ASAN_ERRORS},
    helper::{FridaHelper, FridaInstrumentationHelper, MAP_SIZE},
    FridaOptions,
};

struct FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    base: TimeoutExecutor<InProcessExecutor<'a, H, I, OT, S>>,
    /// Frida's dynamic rewriting engine
    stalker: Stalker<'a>,
    /// User provided callback for instrumentation
    helper: &'c mut FH,
    followed: bool,
    _phantom: PhantomData<&'b u8>,
}

impl<'a, 'b, 'c, EM, FH, H, I, OT, S, Z> Executor<EM, I, S, Z>
    for FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// Instruct the target about the input and run
    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.helper.pre_exec(input);
        if self.helper.stalker_enabled() {
            if self.followed {
                self.stalker.activate(NativePointer(
                    self.base.inner().harness_mut() as *mut _ as *mut c_void
                ))
            } else {
                self.followed = true;
                self.stalker
                    .follow_me::<NoneEventSink>(self.helper.transformer(), None);
            }
        }
        let res = self.base.run_target(fuzzer, state, mgr, input);
        if self.helper.stalker_enabled() {
            self.stalker.deactivate();
        }
        if unsafe { ASAN_ERRORS.is_some() && !ASAN_ERRORS.as_ref().unwrap().is_empty() } {
            println!("Crashing target as it had ASAN errors");
            unsafe {
                libc::raise(libc::SIGABRT);
            }
        }
        if self.helper.stalker_enabled() {
            self.stalker.deactivate();
        }
        self.helper.post_exec(input);
        res
    }
}

impl<'a, 'b, 'c, FH, H, I, OT, S> HasObservers<OT>
    for FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&I) -> ExitKind,
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
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}

impl<'a, 'b, 'c, FH, H, I, OT, S> FridaInProcessExecutor<'a, 'b, 'c, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&I) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(
        gum: &'a Gum,
        base: InProcessExecutor<'a, H, I, OT, S>,
        helper: &'c mut FH,
        timeout: Duration,
    ) -> Self {
        let mut stalker = Stalker::new(gum);

        for range in helper.ranges().gaps(&(0..usize::MAX)) {
            println!("excluding range: {:x}-{:x}", range.start, range.end);
            stalker.exclude(&MemoryRange::new(
                NativePointer(range.start as *mut c_void),
                range.end - range.start,
            ));
        }

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

    let matches = App::new("libafl_frida")
        .version("0.1.0")
        .arg(
            Arg::with_name("cores")
                .short("c")
                .long("cores")
                .value_name("CORES")
                .required(true)
                .takes_value(true),
        )
        .arg(Arg::with_name("harness").required(true).index(1))
        .arg(Arg::with_name("symbol").required(true).index(2))
        .arg(
            Arg::with_name("modules_to_instrument")
                .required(true)
                .index(3),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("OUTPUT")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("b2baddr")
                .short("B")
                .long("b2baddr")
                .value_name("B2BADDR")
                .required(false)
                .takes_value(true),
        )
        .get_matches();

    let cores = parse_core_bind_arg(&matches.value_of("cores").unwrap().to_string()).unwrap();

    color_backtrace::install();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let broker_addr = matches
        .value_of("b2baddr")
        .map(|addrstr| addrstr.parse().unwrap());

    unsafe {
        fuzz(
            matches.value_of("harness").unwrap(),
            matches.value_of("symbol").unwrap(),
            &matches
                .value_of("modules_to_instrument")
                .unwrap()
                .split(':')
                .map(|module_name| std::fs::canonicalize(module_name).unwrap())
                .collect::<Vec<_>>(),
            //modules_to_instrument,
            &[PathBuf::from("./corpus")],
            &PathBuf::from("./crashes"),
            1337,
            &cores,
            matches.value_of("output"),
            broker_addr,
        )
        .expect("An error occurred while fuzzing");
    }
}

/// Not supported on windows right now
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn fuzz(
    _module_name: &str,
    _symbol_name: &str,
    _corpus_dirs: &[PathBuf],
    _objective_dir: &Path,
    _broker_port: u16,
    _cores: &[usize],
    _stdout_file: Option<&str>,
    _broker_addr: Option<SocketAddr>,
) -> Result<(), ()> {
    todo!("Example not supported on Windows");
}

/// The actual fuzzer
#[cfg(unix)]
#[allow(clippy::too_many_lines, clippy::clippy::too_many_arguments)]
unsafe fn fuzz(
    module_name: &str,
    symbol_name: &str,
    modules_to_instrument: &[PathBuf],
    corpus_dirs: &[PathBuf],
    objective_dir: &Path,
    broker_port: u16,
    cores: &[usize],
    stdout_file: Option<&str>,
    broker_addr: Option<SocketAddr>,
) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = MultiStats::new(|s| println!("{}", s));

    #[cfg(target_os = "android")]
    AshmemService::start().expect("Failed to start Ashmem service");
    let shmem_provider = StdShMemProvider::new()?;

    let mut run_client = |state: Option<StdState<_, _, _, _, _>>, mut mgr| {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.

        let lib = libloading::Library::new(module_name).unwrap();
        let target_func: libloading::Symbol<
            unsafe extern "C" fn(data: *const u8, size: usize) -> i32,
        > = lib.get(symbol_name.as_bytes()).unwrap();

        let mut frida_harness = move |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            (target_func)(buf.as_ptr(), buf.len());
            ExitKind::Ok
        };

        let gum = Gum::obtain();
        let frida_options = FridaOptions::parse_env_options();
        let mut frida_helper = FridaInstrumentationHelper::new(
            &gum,
            &frida_options,
            module_name,
            &modules_to_instrument,
        );

        // Create an observation channel using the coverage map
        let edges_observer = HitcountsMapObserver::new(StdMapObserver::new_from_ptr(
            "edges",
            frida_helper.map_ptr(),
            MAP_SIZE,
        ));

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

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
                OnDiskCorpus::new(PathBuf::from("./corpus_discovered")).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new_save_meta(
                    objective_dir.to_path_buf(),
                    Some(OnDiskMetadataFormat::JsonPretty),
                )
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
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
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
                tuple_list!(
                    edges_observer,
                    time_observer,
                    AsanErrorsObserver::new(&ASAN_ERRORS)
                ),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?,
            &mut frida_helper,
            Duration::new(10, 0),
        );

        // In case the corpus is empty (on first run), reset
        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &corpus_dirs));
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    Launcher::builder()
        .shmem_provider(shmem_provider)
        .stats(stats)
        .run_client(&mut run_client)
        .cores(cores)
        .broker_port(broker_port)
        .stdout_file(stdout_file)
        .remote_broker_addr(broker_addr)
        .build()
        .launch()
}
