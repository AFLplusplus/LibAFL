use libafl::prelude::*;

let mut shmem_provider = UnixShMemProvider::new().unwrap();

let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
shmem.write_to_env("__AFL_SHM_ID").unwrap();
let shmem_buf = shmem.as_mut_slice();;

let observer = HitcountsMapObserver::new(StdMapObserver::new());

let mut feedback =  feedback_or!(
	MaxMapFeedback::new(&observer),
	TimeObserver::new()
);

let mut objective = CrashFeedback::new();

let mut state = StdState::new(
	StdRand::with_seed(current_nanos()),
	InMemoryCorpus::new(),
	OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
	&mut feedback,
	&mut objective,
)
.unwrap();

let mon = SimpleMonitor::new(|s| println!("{s}");

let mut mgr = LlmpEventManager::new(mon).unwrap();

let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

let mut executor = ForkserverExecutor::new();

let mut generator = RandBytesGenerator::new(32);

state
	.generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
	.expect("Failed to generate the initial corpus");

let mutator = StdScheduledMutator::new(havoc_mutations());

let mut stages = tuple_list!(StdMutationalStage::new());

