//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use clap::{App, Arg};

use libafl::{
    bolts::tuples::tuple_list,
    corpus::{
        ondisk::OnDiskMetadataFormat, Corpus, InMemoryCorpus,
        IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus, QueueCorpusScheduler,
    },
    events::EventManager,
    executors::{
        inprocess::InProcessExecutor, timeout::TimeoutExecutor, Executor, ExitKind, HasExecHooks,
        HasExecHooksTuple, HasObservers, HasObserversHooks,
    },
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{HasTargetBytes, Input},
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    mutators::token_mutations::Tokens,
    observers::{HitcountsMapObserver, ObserversTuple, StdMapObserver},
    bolts::{
        os::ashmem_server::AshmemService,
        shmem::{StdShMemProvider, ShMemProvider},
    },
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, State},
    stats::SimpleStats,
    utils::{current_nanos, launcher, parse_core_bind_arg, StdRand},
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

struct FridaInProcessExecutor<'a, 'b, 'c, EM, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    base: TimeoutExecutor<InProcessExecutor<'a, EM, H, I, OT, S>, I>,
    /// Frida's dynamic rewriting engine
    stalker: Stalker<'a>,
    /// User provided callback for instrumentation
    helper: &'c mut FH,
    followed: bool,
    _phantom: PhantomData<&'b u8>,
}

impl<'a, 'b, 'c, EM, FH, H, I, OT, S> Executor<I>
    for FridaInProcessExecutor<'a, 'b, 'c, EM, FH, H, I, OT, S>
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
        if self.helper.stalker_enabled() {
            self.stalker.deactivate();
        }
if unsafe { ASAN_ERRORS.is_some() && !ASAN_ERRORS.as_ref().unwrap().is_empty() } {
            println!("Crashing target as it had ASAN errors");
            unsafe {
                libc::raise(libc::SIGABRT);
            }
        }
        res
    }
}

impl<'a, 'b, 'c, EM, FH, H, I, OT, S> HasExecHooks<EM, I, S>
    for FridaInProcessExecutor<'a, 'b, 'c, EM, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// Called right before exexution starts
    #[inline]
    fn pre_exec(&mut self, state: &mut S, event_mgr: &mut EM, input: &I) -> Result<(), Error> {
        self.helper.pre_exec(input);
        self.base.pre_exec(state, event_mgr, input)
    }

    /// Called right after execution finished.
    #[inline]
    fn post_exec(&mut self, state: &mut S, event_mgr: &mut EM, input: &I) -> Result<(), Error> {
        self.helper.post_exec(input);
        self.base.post_exec(state, event_mgr, input)
    }
}

impl<'a, 'b, 'c, EM, FH, H, I, OT, S> HasObservers<OT>
    for FridaInProcessExecutor<'a, 'b, 'c, EM, FH, H, I, OT, S>
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

impl<'a, 'b, 'c, EM, FH, H, I, OT, S> HasObserversHooks<EM, I, OT, S>
    for FridaInProcessExecutor<'a, 'b, 'c, EM, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S>,
{
}

impl<'a, 'b, 'c, EM, FH, H, I, OT, S> FridaInProcessExecutor<'a, 'b, 'c, EM, FH, H, I, OT, S>
where
    FH: FridaHelper<'b>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(
        gum: &'a Gum,
        base: InProcessExecutor<'a, EM, H, I, OT, S>,
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

    let matches = App::new("libafl_frida")
        .version("0.1.0")
        .arg(Arg::with_name("cores")
            .short("c")
            .long("cores")
            .value_name("CORES")
            .required(true)
            .takes_value(true)
        )
        .arg(Arg::with_name("harness")
            .required(true)
            .index(1)
        )
        .arg(Arg::with_name("symbol")
            .required(true)
            .index(2)
        )
        .arg(Arg::with_name("modules_to_instrument")
            .required(true)
            .index(3)
        )
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("OUTPUT")
            .required(false)
            .takes_value(true)
        )
        .get_matches();

    let cores = parse_core_bind_arg(matches.value_of("cores").unwrap().to_string()).unwrap();

    color_backtrace::install();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );


    unsafe {
        fuzz(
            matches.value_of("harness").unwrap(),
            matches.value_of("symbol").unwrap(),
            matches.value_of("modules_to_instrument")
                .unwrap()
                .split(':')
                .map(|module_name| std::fs::canonicalize(module_name).unwrap())
                .collect(),
            &vec![PathBuf::from("./corpus")],
            &PathBuf::from("./crashes"),
            1337,
            &cores,
            matches.value_of("output"),
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
    _cores: &[usize],
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
    objective_dir: &PathBuf,
    broker_port: u16,
    cores: &[usize],
    stdout_file: Option<&str>,
) -> Result<(), Error> {
    let stats_closure = |s| {
        println!("{}", s)
    };
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(stats_closure);


    #[cfg(target_os = "android")]
    AshmemService::start().expect("Failed to start Ashmem service");
    let shmem_provider = StdShMemProvider::new()?;

    let mut client_init_stats = || {
        Ok(SimpleStats::new(stats_closure))
    };

    let mut run_client = |state: Option<State<_, _, _, _, _, _>>, mut mgr| {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.

        let lib = libloading::Library::new(module_name).unwrap();
        let target_func: libloading::Symbol<unsafe extern "C" fn(data: *const u8, size: usize) -> i32> =
            lib.get(symbol_name.as_bytes()).unwrap();

        let mut frida_harness = move |buf: &[u8]| {
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

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            State::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Feedbacks to rate the interestingness of an input
                MaxMapFeedback::new_with_observer_track(&edges_observer, true, false),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new_save_meta(objective_dir.clone(), Some(OnDiskMetadataFormat::JsonPretty))
                    .unwrap(),
                // Feedbacks to recognize an input as solution
                feedback_or!(
                    CrashFeedback::new(),
                    TimeoutFeedback::new(),
                    AsanErrorsFeedback::new()
                ),
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
        let stage = StdMutationalStage::new(mutator);

        // A fuzzer with just one stage and a minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());
        let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

        frida_helper.register_thread();
        // Create the executor for an in-process function with just one observer for edge coverage
        let mut executor = FridaInProcessExecutor::new(
            &gum,
            InProcessExecutor::new(
                &mut frida_harness,
                tuple_list!(edges_observer, AsanErrorsObserver::new(&ASAN_ERRORS)),
                &mut state,
                &mut mgr,
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
                .load_initial_inputs(&mut executor, &mut mgr, &scheduler, &corpus_dirs)
                .unwrap_or_else(|_| panic!(
                    "Failed to load initial corpus at {:?}",
                    &corpus_dirs
                ));
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        fuzzer.fuzz_loop(&mut state, &mut executor, &mut mgr, &scheduler)?;

        // Never reached

        Ok(())
    };

    launcher(shmem_provider.clone(), stats, &mut client_init_stats, &mut run_client, broker_port, cores, stdout_file)
}
