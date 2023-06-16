use std::path::{Path, PathBuf};

use libafl::{
    bolts::{
        core_affinity::{CoreId, Cores},
        launcher::Launcher,
        rands::{RandomSeed, StdRand},
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
    },
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus, Testcase},
    events::EventConfig,
    feedbacks::{CrashFeedback, MaxMapFeedback},
    inputs::BytesInput,
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::StdMapObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::StdState,
    Error, Fuzzer, StdFuzzer,
};
use libafl_nyx::{executor::NyxExecutor, helper::NyxHelper};

fn main() {
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");
    let broker_port = 7777;

    let monitor = MultiMonitor::new(|s| println!("{s}"));

    let cores = Cores::all().expect("unable to get all core id");
    let parent_cpu_id = cores.ids.first().expect("unable to get first core id");

    // region: fuzzer start function
    let mut run_client = |state: Option<_>, mut restarting_mgr, core_id: CoreId| {
        // nyx shared dir, created by nyx-fuzz/packer/packer/nyx_packer.py
        let share_dir = Path::new("/tmp/nyx_libxml2/");
        let cpu_id = core_id.0.try_into().unwrap();
        let parallel_mode = true;
        // nyx stuff
        let mut helper = NyxHelper::new(
            share_dir,
            cpu_id,
            true,
            parallel_mode,
            Some(parent_cpu_id.0.try_into().unwrap()),
        )
        .unwrap();
        let observer =
            unsafe { StdMapObserver::from_mut_ptr("trace", helper.trace_bits, helper.map_size) };

        let input = BytesInput::new(b"22".to_vec());
        let rand = StdRand::new();
        let mut corpus = CachedOnDiskCorpus::new(PathBuf::from("./corpus_discovered"), 64).unwrap();
        corpus
            .add(Testcase::new(input))
            .expect("error in adding corpus");
        let solutions = OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap();

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
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }

    // endregion
}
