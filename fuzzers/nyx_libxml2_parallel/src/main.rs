use std::path::{Path, PathBuf};

use libafl::bolts::launcher::Launcher;
use libafl::bolts::rands::StdRand;
use libafl::bolts::shmem::ShMemProvider;
use libafl::events::EventConfig;
use libafl::Error;
use libafl::{
    bolts::{core_affinity::Cores, rands::RandomSeed, shmem::StdShMemProvider, tuples::tuple_list},
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Fuzzer, StdFuzzer,
};
use libafl_nyx::executor::NyxExecutor;
use libafl_nyx::helper::NyxHelper;

fn main() {
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let broker_port = 7777;

    let monitor = MultiMonitor::new(|s| println!("{}", s));

    let cores = Cores::from_cmdline("0-3").unwrap();
    let parent_cpu_id = 0;
    assert!(cores.contains(parent_cpu_id),"parent_cpu_id is not in range of cores");

    // region: fuzzer start function
    let mut run_client = |state: Option<_>, mut restarting_mgr, _core_id: usize| {
        // nyx shared dir, created by nyx-fuzz/packer/packer/nyx_packer.py
        let share_dir = Path::new("/tmp/nyx_libxml2/");
        let cpu_id = _core_id as u32;
        let parallel_mode = true;
        // nyx stuff
        let mut helper = NyxHelper::new(
            share_dir,
            cpu_id,
            true,
            parallel_mode,
            Some(parent_cpu_id as u32),
        )
        .unwrap();
        let trace_bits =
            unsafe { std::slice::from_raw_parts_mut(helper.trace_bits, helper.map_size) };
        let observer = StdMapObserver::new("trace", trace_bits);

        let input = BytesInput::new(b"22".to_vec());
        let rand = StdRand::new();
        let mut corpus = InMemoryCorpus::new();
        corpus
            .add(Testcase::new(input))
            .expect("error in adding corpus");
        let solutions = OnDiskCorpus::<BytesInput>::new(PathBuf::from("./crashes")).unwrap();

        // libafl stuff
        let mut feedback = MaxMapFeedback::new(&observer);
        let mut objective = CrashFeedback::new();
        let scheduler = RandScheduler::new();
        let mut executor = NyxExecutor::new(&mut helper, tuple_list!(observer)).unwrap();

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap()
        });

        println!("We're a client, let's fuzz :)");
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut restarting_mgr)?;
        Ok(())
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_name("default"))
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(broker_port)
        // .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }

    // endregion
}
