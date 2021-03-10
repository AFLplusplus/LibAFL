//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use libafl::{
    bolts::{
        shmem::UnixShMem,
        tuples::{tuple_list, Named},
    },
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    events::{setup_restarting_mgr, EventManager},
    executors::{inprocess::InProcessExecutor, Executor, ExitKind, HasObservers},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, HasCorpusScheduler, StdFuzzer},
    inputs::{HasTargetBytes, Input},
    mutators::{scheduled::HavocBytesMutator, token_mutations::Tokens},
    observers::{HitcountsMapObserver, ObserversTuple, StdMapObserver},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, State},
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
    Error,
};
use std::{env, path::PathBuf, ptr};

use frida_gum::stalker::{NoneEventSink, Stalker, Transformer};
use frida_gum::{Gum, Module};

use lazy_static::lazy_static;
use libloading;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}

/// An helper that feeds FridaInProcessExecutor with user-supplied instrumentation
pub trait FridaHelper<'a> {
    fn transformer(&self) -> &Transformer<'a>;
}

const MAP_SIZE: usize = 64 * 1024;

/// An helper that feeds FridaInProcessExecutor with edge-coverage instrumentation
struct FridaEdgeCoverageHelper<'a> {
    map: [u8; MAP_SIZE],
    previous_pc: u64,
    base_address: u64,
    size: usize,
    /// Transformer that has to be passed to FridaInProcessExecutor
    transformer: Option<Transformer<'a>>,
}

impl<'a> FridaHelper<'a> for FridaEdgeCoverageHelper<'a> {
    fn transformer(&self) -> &Transformer<'a> {
        self.transformer.as_ref().unwrap()
    }
}

/// The implementation of the FridaEdgeCoverageHelper
impl<'a> FridaEdgeCoverageHelper<'a> {
    /// Constructor function to create a new FridaEdgeCoverageHelper, given a module_name.
    pub fn new(module_name: &str) -> Self {
        let mut helper = Self {
            map: [0u8; MAP_SIZE],
            previous_pc: 0x0,
            base_address: Module::find_base_address(module_name).0 as u64,
            size: FridaEdgeCoverageHelper::get_module_size(module_name),
            transformer: None,
        };

        // Let's exclude the main module and libc.so at least:
        //helper.stalker.exclude(&MemoryRange::new(Module::find_base_address(&env::args().next().unwrap()), FridaEdgeCoverageHelper::get_module_size(&env::args().next().unwrap())));
        //helper.stalker.exclude(&MemoryRange::new(Module::find_base_address("libc.so"), FridaEdgeCoverageHelper::get_module_size("libc.so")));

        let transformer = Transformer::from_callback(&GUM, |basic_block, _output| {
            let mut first = true;
            for instruction in basic_block {
                if first {
                    let address = unsafe { (*instruction.get_instruction()).address };
                    if address >= helper.base_address
                        && address <= helper.base_address + helper.size as u64
                    {
                        instruction.put_callout(|cpu_context| {
                            #[cfg(target_arch = "x86_64")]
                            let mut current_pc = cpu_context.rip();
                            #[cfg(target_arch = "aarch64")]
                            let mut current_pc = cpu_context.pc();

                            current_pc = (current_pc >> 4) ^ (current_pc << 8);

                            current_pc &= MAP_SIZE as u64 - 1;
                            //println!("current_pc after mask: {:x}, helper.previous_pc: {:x}", current_pc, helper.previous_pc);

                            helper.map[(current_pc ^ helper.previous_pc) as usize] += 1;
                            helper.previous_pc = current_pc >> 1;
                        });
                    }
                    first = false;
                }
                instruction.keep()
            }
        });

        helper.transformer = Some(transformer);
        helper
    }

    /// Helper function to get the size of a module's CODE section from frida
    pub fn get_module_size(module_name: &str) -> usize {
        let mut code_size = 0;
        let code_size_ref = &mut code_size;
        Module::enumerate_ranges(
            module_name,
            frida_gum::PageProtection::ReadExecute,
            move |details, _user_data| {
                *code_size_ref = details.memory_range().size() as usize;
                0
            },
            ptr::null_mut(),
        );

        code_size
    }
}

struct FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    base: InProcessExecutor<'a, H, I, OT>,
    /// Frida's dynamic rewriting engine
    stalker: Stalker<'a>,
    /// User provided callback for instrumentation
    helper: &'a FH,
    followed: bool,
}

impl<'a, FH, H, I, OT> Executor<I> for FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// Called right before exexution starts
    #[inline]
    fn pre_exec<EM, S>(&mut self, state: &mut S, event_mgr: &mut EM, input: &I) -> Result<(), Error>
    where
        EM: EventManager<I, S>,
    {
        if !self.followed {
            self.followed = true;
            self.stalker
                .follow_me::<NoneEventSink>(self.helper.transformer(), None);
        }
        self.base.pre_exec(state, event_mgr, input)
    }

    /// Instruct the target about the input and run
    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        self.base.run_target(input)
    }

    /// Called right after execution finished.
    #[inline]
    fn post_exec<EM, S>(&mut self, state: &S, event_mgr: &mut EM, input: &I) -> Result<(), Error>
    where
        EM: EventManager<I, S>,
    {
        self.base.post_exec(state, event_mgr, input)
    }
}

impl<'a, FH, H, I, OT> HasObservers<OT> for FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a>,
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

impl<'a, FH, H, I, OT> Named for FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    fn name(&self) -> &str {
        self.base.name()
    }
}

impl<'a, FH, H, I, OT> FridaInProcessExecutor<'a, FH, H, I, OT>
where
    FH: FridaHelper<'a>,
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    pub fn new(base: InProcessExecutor<'a, H, I, OT>, helper: &'a FH) -> Self {
        Self {
            base: base,
            stalker: Stalker::new(&GUM),
            helper: helper,
            followed: false,
        }
    }
}

/// The main fn, usually parsing parameters, and starting the fuzzer
pub fn main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    unsafe {
        fuzz(
            &env::args().nth(1).expect("no module specified"),
            &env::args().nth(2).expect("no symbol specified"),
            vec![PathBuf::from("./corpus")],
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
    corpus_dirs: Vec<PathBuf>,
    objective_dir: PathBuf,
    broker_port: u16,
) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(|s| println!("{}", s));

    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) =
        match setup_restarting_mgr::<_, _, UnixShMem, _>(stats, broker_port) {
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

    let lib = libloading::Library::new(module_name).unwrap();
    let target_func: libloading::Symbol<unsafe extern "C" fn(data: *const u8, size: usize) -> i32> =
        lib.get(symbol_name.as_bytes()).unwrap();
    let mut frida_helper = FridaEdgeCoverageHelper::new(module_name);

    // Create an observation channel using the coverage map
    let edges_observer = HitcountsMapObserver::new(StdMapObserver::new_from_ptr(
        "edges",
        frida_helper.map.as_mut_ptr(),
        MAP_SIZE,
    ));

    let mut frida_harness = move |buf: &[u8]| {
        (target_func)(buf.as_ptr(), buf.len());
        ExitKind::Ok
    };

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        State::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Feedbacks to rate the interestingness of an input
            tuple_list!(MaxMapFeedback::new_with_observer_track(
                &edges_observer,
                true,
                false
            )),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // Feedbacks to recognize an input as solution
            tuple_list!(CrashFeedback::new()),
        )
    });

    println!("We're a client, let's fuzz :)");

    // Create a PNG dictionary if not existing
    if state.metadata().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::new(vec![
            vec![137, 80, 78, 71, 13, 10, 26, 10], // PNG header
            "IHDR".as_bytes().to_vec(),
            "IDAT".as_bytes().to_vec(),
            "PLTE".as_bytes().to_vec(),
            "IEND".as_bytes().to_vec(),
        ]));
    }

    // Setup a basic mutator with a mutational stage
    let mutator = HavocBytesMutator::default();
    let stage = StdMutationalStage::new(mutator);

    // A fuzzer with just one stage and a minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());
    let fuzzer = StdFuzzer::new(scheduler, tuple_list!(stage));

    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = FridaInProcessExecutor::new(
        InProcessExecutor::new(
            "in-process(edges)",
            &mut frida_harness,
            tuple_list!(edges_observer),
            &mut state,
            &mut restarting_mgr,
        )?,
        &frida_helper,
    );

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(
                &mut executor,
                &mut restarting_mgr,
                fuzzer.scheduler(),
                &corpus_dirs,
            )
            .expect(&format!(
                "Failed to load initial corpus at {:?}",
                &corpus_dirs
            ));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut state, &mut executor, &mut restarting_mgr)?;

    // Never reached
    Ok(())
}
