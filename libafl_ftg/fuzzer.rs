use libafl::prelude::*;

let observer = HitcountsMapObserver::new(StdMapObserver::new());

let mut feedback =  feedback_or!(MaxMapFeedback::new(&observer), TimeObserver::new());

let mut objective = CrashFeedback::new();

let mut state = StdState::new(StdRand::with_seed(current_nanos()), InMemoryCorpus::new(), OnDiskCorpus::new(PathBuf::from()).unwrap(), &mut feedback, &mut objective,).unwrap();

let mon = SimpleMonitor::new();

let mut mgr = LlmpRestartingEventManager::new(mon);

let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

let mut executor = ForkserverExecutor::new();

let mutator = StdScheduledMutator::new();

let mut stages = StdMutationalStage::new();

