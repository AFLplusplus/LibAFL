//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use core::ops::{Deref, DerefMut};

use std::{env, path::PathBuf, ptr};
#[cfg(unix)]
use libafl::{
    bolts::{shmem::UnixShMem, tuples::tuple_list},
    corpus::{
        Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
        QueueCorpusScheduler,
    },
    events::setup_restarting_mgr,
    executors::{inprocess::InProcessExecutor, Executor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, HasCorpusScheduler, StdFuzzer},
    inputs::{Input, BytesInput, HasTargetBytes},
    mutators::{scheduled::HavocBytesMutator, token_mutations::Tokens},
    observers::{HitcountsMapObserver, StdMapObserver, ObserversTuple},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasMetadata, State},
    stats::SimpleStats,
    utils::{current_nanos, StdRand},
    Error,
};

use frida_gum::{Module, Gum, CpuContext, NativePointer, MemoryRange};
use frida_gum::stalker::{NoneEventSink, Stalker, StalkerIterator, StalkerOutput, Transformer};

use std::pin::Pin;
use std::rc::Rc;
use libc::c_void;
use lazy_static::lazy_static;
use libloading;

/// We will interact with a C++ target, so use external c functionality
#[cfg(unix)]
extern "C" {
    // /// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
    //fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32;

    // afl_libfuzzer_init calls LLVMFUzzerInitialize()
    //fn afl_libfuzzer_init() -> i32;
}

lazy_static!{
    static ref GUM: Gum = unsafe { Gum::obtain() };
}

/// A helper object to manage the frida stuff
struct FridaHelper<'a> {
    stalker: Stalker<'a>,
    transformer: Option<Transformer<'a>>,
    map: [u8; 64 * 1024],
    previous_pc: u64,
    followed: bool,
    base_address: u64,
    size: usize,
}

//impl<'a, T> Deref for FridaHelper<'a> {
    //fn deref(&self) -> &Self:T {
        //&self.stalker;
    //}
//}

//impl<'a, T> DerefMut for FridaHelper<'a>
//where
    //T: Stalker,
//{
    //fn deref_mut(&self) -> &mut Self:T {
        //&mut self.stalker;
    //}
//}
unsafe impl<'a> Sync for FridaHelper<'a> {}

fn get_module_size<'a>(module_name: &str) -> usize {
    let mut code_size = 0;
    let code_size_ref = &mut code_size;
    Module::enumerate_ranges(module_name, frida_gum_sys::_GumPageProtection_GUM_PAGE_READ | frida_gum_sys::_GumPageProtection_GUM_PAGE_EXECUTE,
                             move |details, _user_data| {
        *code_size_ref = details.get_memory_range().size() as usize;
        0
    }, ptr::null_mut());

    code_size
}

#[cfg(unix)]
impl<'a> FridaHelper<'a> {
    pub fn new(module_name: &str) -> FridaHelper<'a> {
        let helper = Self {
            stalker: Stalker::new(&GUM),
            transformer: None,
            map: [0u8; 64 * 1024],
            previous_pc: 0x0,
            followed: false,
            base_address: 0u64,
            size: 0,
        };

        let mut pinned_helper = helper;

        let base_address = Module::find_base_address(module_name);
        let mut code_size = get_module_size(module_name);

        println!("base address: {:?}, code_size: {}", base_address, code_size);
        pinned_helper.base_address = base_address.0 as u64;
        pinned_helper.size = code_size;

        pinned_helper.stalker.exclude(&MemoryRange::new(Module::find_base_address(&env::args().nth(0).unwrap()), get_module_size(&env::args().nth(0).unwrap())));
        pinned_helper.stalker.exclude(&MemoryRange::new(Module::find_base_address("libc.so"), get_module_size("libc.so")));

        //let base = pinned_helper.base_address;
        //let end = pinned_helper.base_address + pinned_helper.size as u64;
        pinned_helper.transformer = Some(Transformer::from_callback(&GUM, |basic_block, _output| {
            let mut first = true;
            for instruction in basic_block {
                if first {
                    let address = unsafe { (*instruction.get_instruction()).address };
                    if address >= pinned_helper.base_address && address <= pinned_helper.base_address + pinned_helper.size as u64 {
                         instruction.put_callout(|cpu_context| {
                            //println!("previous: {:x}", pinned_helper.previous_pc);
                            #[cfg(target_arch = "x86_64")]
                            let mut current_pc = cpu_context.rip();
                            #[cfg(target_arch = "aarch4")]
                            let mut current_pc = cpu_context.pc();

                            current_pc = (current_pc >> 4) ^ (current_pc << 8);

                            current_pc &= (64 * 1024) - 1;
                            //println!("current_pc after mask: {:x}, helper.previous_pc: {:x}", current_pc, pinned_helper.previous_pc);

                            pinned_helper.map[(current_pc ^ pinned_helper.previous_pc) as usize] += 1;
                            pinned_helper.previous_pc = current_pc >> 1;
                        });
                    }
                    first = false;
                }
                instruction.keep()
            }
        }));

        //let range = MemoryRange::new(NativePointer(0x00007ffff7a89000 as *mut c_void), 0x1bd000);
        //pinned_helper.stalker.exclude(&range);
        pinned_helper

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
fn fuzz(_module_name: &str, _symbol_name: &str, _corpus_dirs: Vec<PathBuf>, _objective_dir: PathBuf, _broker_port: u16) -> Result<(), ()> {
    todo!("Example not supported on Windows");
}

/// The actual fuzzer
#[cfg(unix)]
unsafe fn fuzz(module_name: &str, symbol_name: &str, corpus_dirs: Vec<PathBuf>, objective_dir: PathBuf, broker_port: u16) -> Result<(), Error> {
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
    let target_func: libloading::Symbol<unsafe extern fn(data: *const u8, size: usize) -> i32> = lib.get(symbol_name.as_bytes()).unwrap();
    let mut frida_helper = FridaHelper::new(module_name);

    // Create an observation channel using the coverage map
    let edges_observer = HitcountsMapObserver::new(unsafe {
        StdMapObserver::new_from_ptr("edges", frida_helper.map.as_mut_ptr(), 64*1024)
    });


    let mut frida_harness = move |_executor: &'_ InProcessExecutor<_, _>, buf: &'_ [u8]| {
        //println!("{:?}", buf);
        if !frida_helper.followed {
            println!("not yet followed!");
            let transformer = frida_helper.transformer.as_ref().unwrap();
            //frida_helper.stalker.set_trust_threshold(0);
            frida_helper.followed = true;
            frida_helper.stalker.follow_me::<NoneEventSink>(transformer, None);
        } else {
            //frida_helper.stalker.activate(NativePointer(LLVMFuzzerTestOneInput as *mut c_void));
        }
        unsafe {
            (target_func)(buf.as_ptr(), buf.len());
            //LLVMFuzzerTestOneInput(buf.as_ptr(), buf.len());
        }
        //frida_helper.stalker.deactivate();
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


    //
    //
    // Create the executor for an in-process function with just one observer for edge coverage
    let mut executor = InProcessExecutor::new(
        "in-process(edges)",
        &mut frida_harness,
        tuple_list!(edges_observer),
        &mut state,
        &mut restarting_mgr,
    )?;

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    //unsafe {
        //if afl_libfuzzer_init() == -1 {
            //println!("Warning: LLVMFuzzerInitialize failed with -1")
        //}
    //}

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
