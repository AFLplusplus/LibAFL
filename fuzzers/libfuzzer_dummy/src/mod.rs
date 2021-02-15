//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.

use std::{path::PathBuf};
use std::io::{self, BufRead};

use libafl::{
    bolts::{tuples::tuple_list, shmem::UnixShMem},
    corpus::{Corpus, InMemoryCorpus},
    events::setup_restarting_mgr,
    stats::{SimpleStats},
    executors::{inprocess::InProcessExecutor, Executor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    inputs::Input,
    mutators::{scheduled::HavocBytesMutator, HasMaxSize},
    observers::StdMapObserver,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, State},
    utils::StdRand,
    Error, Fuzzer, StdFuzzer,
};

/// The name of the coverage map observer, to find it again in the observer list
const NAME_COV_MAP: &str = "cov_map";

static mut EDGES_MAP: [u8; 32] = [0; 32];
static EDGES_SIZE: u32 = 32;

/// The wrapped harness function, calling out to the llvm-style libfuzzer harness
fn harness<E, I>(_executor: &E, buf: &[u8]) -> ExitKind
where
    E: Executor<I>,
    I: Input,
{
    //println!("{:?}", buf);

    unsafe {
      EDGES_MAP[0] = 1;
      if buf.len() > 0 && buf[0] == 'a' as u8 {
        EDGES_MAP[2] = 1;
        if buf.len() > 1 && buf[1] == 'b'  as u8 {
          EDGES_MAP[3] = 1;
            //std::process::abort();
        }
      }
    }
    ExitKind::Ok
}

/// The main fn, parsing parameters, and starting the fuzzer
pub fn main() {
    fuzz(Some(vec![PathBuf::from("./corpus")]), 1337).expect("An error occurred while fuzzing");
}

/// The actual fuzzer
fn fuzz(input: Option<Vec<PathBuf>>, broker_port: u16) -> Result<(), Error> {
    let mut rand = StdRand::new(0);
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let stats = SimpleStats::new(|s| println!("{}", s));
    
    println!("NEW START");
    let stdin = io::stdin();
    let _ = stdin.lock().lines().next().unwrap().unwrap();
    
    // The restarting state will spawn the same process again as child, then restartet it each time it crashes.
    let (state_opt, mut restarting_mgr) =
        setup_restarting_mgr::<_, _, _, _, _, _, UnixShMem, _>(stats, broker_port).expect("Failed to setup the restarter".into());

    let edges_observer =
    StdMapObserver::new_from_ptr(&NAME_COV_MAP, unsafe { &mut EDGES_MAP[0] as *mut u8 }, EDGES_SIZE as usize);

    let mut state = match state_opt {
        Some(s) => s,
        None => {
            State::new(
                InMemoryCorpus::new(),
                tuple_list!(MaxMapFeedback::new_with_observer(
                    &NAME_COV_MAP,
                    &edges_observer
                )),
                InMemoryCorpus::new(),
                tuple_list!(CrashFeedback::new()),
            )
        },
    };

    println!("We're a client, let's fuzz :)");

    let mut mutator = HavocBytesMutator::new_default();
    mutator.set_max_size(4096);
    let stage = StdMutationalStage::new(mutator);
    let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

    // Create the executor
    let mut executor = InProcessExecutor::new(
        "Libfuzzer",
        harness,
        tuple_list!(edges_observer),
        &mut state,
        &mut restarting_mgr,
    );

    // The actual target run starts here.

    // in case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        match input {
            Some(x) => state
                .load_initial_inputs(&mut executor, &mut restarting_mgr, &x)
                .expect(&format!("Failed to load initial corpus at {:?}", &x)),
            None => (),
        }
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    fuzzer.fuzz_loop(&mut rand, &mut executor, &mut state, &mut restarting_mgr)
}
