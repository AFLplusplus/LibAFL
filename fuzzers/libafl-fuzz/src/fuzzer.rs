use std::{borrow::Cow, marker::PhantomData, path::PathBuf, time::Duration};

use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, OnDiskCorpus},
    events::{
        CentralizedEventManager, EventManagerHooksTuple, EventProcessor,
        LlmpRestartingEventManager, ProgressReporter,
    },
    executors::forkserver::{ForkserverExecutor, ForkserverExecutorBuilder},
    feedback_and, feedback_or, feedback_or_fast,
    feedbacks::{ConstFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::StdFuzzer,
    inputs::BytesInput,
    mutators::{
        scheduled::havoc_mutations, tokens_mutations, AFLppRedQueen, StdScheduledMutator, Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, QueueScheduler,
        StdWeightedScheduler,
    },
    stages::{
        mutational::MultiMutationalStage, CalibrationStage, ColorizationStage, IfStage,
        StagesTuple, StdMutationalStage, StdPowerMutationalStage, SyncFromDiskStage,
    },
    state::{
        HasCorpus, HasCurrentTestcase, HasExecutions, HasLastReportTime, HasStartTime, StdState,
        UsesState,
    },
    Error, Fuzzer, HasFeedback, HasMetadata, SerdeAny,
};
use libafl_bolts::{
    core_affinity::CoreId,
    current_nanos, current_time,
    fs::get_unique_std_input_file,
    ownedref::OwnedRefMut,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Handled, Merge},
    AsSliceMut,
};
use libafl_targets::{cmps::AFLppCmpLogMap, AFLppCmpLogObserver, AFLppCmplogTracingStage};
use serde::{Deserialize, Serialize};

use crate::{
    afl_stats::AflStatsStage,
    corpus::{set_corpus_filepath, set_solution_filepath},
    env_parser::AFL_DEFAULT_MAP_SIZE,
    feedback::{
        filepath::CustomFilepathToTestcaseFeedback, persistent_record::PersitentRecordFeedback,
        seed::SeedFeedback,
    },
    mutational_stage::SupportedMutationalStages,
    scheduler::SupportedSchedulers,
    Opt, AFL_DEFAULT_INPUT_LEN_MAX, AFL_DEFAULT_INPUT_LEN_MIN, SHMEM_ENV_VAR,
};

pub type LibaflFuzzState =
    StdState<BytesInput, CachedOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>;

pub fn run_client<EMH, SP>(
    state: Option<LibaflFuzzState>,
    mut restarting_mgr: CentralizedEventManager<
        LlmpRestartingEventManager<(), LibaflFuzzState, SP>,
        EMH,
        LibaflFuzzState,
        SP,
    >,
    fuzzer_dir: &PathBuf,
    core_id: CoreId,
    opt: &Opt,
    is_main_node: bool,
) -> Result<(), Error>
where
    EMH: EventManagerHooksTuple<LibaflFuzzState> + Copy + Clone,
    SP: ShMemProvider,
{
    // Create the shared memory map for comms with the forkserver
    let mut shmem_provider = StdShMemProvider::new().unwrap();
    let mut shmem = shmem_provider
        .new_shmem(opt.map_size.unwrap_or(AFL_DEFAULT_MAP_SIZE))
        .unwrap();
    shmem.write_to_env(SHMEM_ENV_VAR).unwrap();
    let shmem_buf = shmem.as_slice_mut();

    // Create an observation channel to keep track of edges hit.
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::new("edges", shmem_buf)).track_indices()
    };

    // Create a MapFeedback for coverage guided fuzzin'
    let map_feedback = MaxMapFeedback::new(&edges_observer);

    // Create the CalibrationStage; used to measure the stability of an input.
    // We run the stage only if we are NOT doing sequential scheduling.
    let calibration = IfStage::new(
        |_, _, _, _| Ok(!opt.sequential_queue),
        tuple_list!(CalibrationStage::new(&map_feedback)),
    );

    // Create a AFLStatsStage;
    let afl_stats_stage = AflStatsStage::new(opt, fuzzer_dir.clone(), &edges_observer);

    // Create an observation channel to keep track of the execution time.
    let time_observer = TimeObserver::new("time");

    /*
     * Feedback to decide if the Input is "corpus worthy"
     * We only check if it gives new coverage.
     * The `TimeFeedback` is used to annotate the testcase with it's exec time.
     * The `CustomFilepathToTestcaseFeedback is used to adhere to AFL++'s corpus format.
     * The `Seedfeedback` is used during seed loading to adhere to AFL++'s handling of seeds
     */
    let mut feedback = SeedFeedback::new(
        feedback_or!(
            map_feedback,
            TimeFeedback::new(&time_observer),
            CustomFilepathToTestcaseFeedback::new(set_corpus_filepath, fuzzer_dir.clone())
        ),
        opt,
    );

    /*
     * Feedback to decide if the Input is "solution worthy".
     * We check if it's a crash or a timeout (if we are configured to consider timeouts)
     * The `CustomFilepathToTestcaseFeedback is used to adhere to AFL++'s corpus format.
     * The `MaxMapFeedback` saves objectives only if they hit new edges
     * Note: The order of the feedbacks matter!
     * */
    let mut objective = feedback_or!(
        feedback_and!(
            feedback_or_fast!(
                CrashFeedback::new(),
                feedback_and!(
                    ConstFeedback::new(!opt.ignore_timeouts),
                    TimeoutFeedback::new()
                )
            ),
            MaxMapFeedback::with_name("edges_objective", &edges_observer)
        ),
        CustomFilepathToTestcaseFeedback::new(set_solution_filepath, fuzzer_dir.clone()),
        PersitentRecordFeedback::new(opt.persistent_record),
    );

    // Initialize our State if necessary
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::with_seed(current_nanos()),
            // TODO: configure testcache size
            CachedOnDiskCorpus::<BytesInput>::new(fuzzer_dir.join("queue"), 1000).unwrap(),
            OnDiskCorpus::<BytesInput>::new(fuzzer_dir.clone()).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    // Create our Mutational Stage.
    // We can either have a simple MutationalStage (for Queue scheduling)
    // Or one that utilizes scheduling metadadata (Weighted Random scheduling)
    let mutation = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
    let mutational_stage = if opt.sequential_queue {
        SupportedMutationalStages::StdMutational(StdMutationalStage::new(mutation), PhantomData)
    } else {
        SupportedMutationalStages::PowerMutational(
            StdPowerMutationalStage::new(mutation),
            PhantomData,
        )
    };

    let strategy = opt.power_schedule.unwrap_or(PowerSchedule::EXPLORE);

    // Create our ColorizationStage
    let colorization = ColorizationStage::new(&edges_observer);

    // Create our Scheduler
    // Our scheduler can either be a Queue
    // Or a "Weighted Random" which prioritizes entries that take less time and hit more edges
    let scheduler;
    if opt.sequential_queue {
        scheduler = SupportedSchedulers::Queue(QueueScheduler::new(), PhantomData);
    } else {
        let mut weighted_scheduler =
            StdWeightedScheduler::with_schedule(&mut state, &edges_observer, Some(strategy));
        if opt.cycle_schedules {
            weighted_scheduler = weighted_scheduler.cycling_scheduler();
        }
        // TODO: Go back to IndexesLenTimeMinimizerScheduler once AflScheduler is implemented for it.
        scheduler = SupportedSchedulers::Weighted(
            IndexesLenTimeMinimizerScheduler::new(&edges_observer, weighted_scheduler),
            PhantomData,
        );
    }

    // Create our Fuzzer
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // Create the base Executor
    let mut executor = base_executor(opt, &mut shmem_provider);
    // Set a custom exit code to be interpreted as a Crash if configured.
    if let Some(crash_exitcode) = opt.crash_exitcode {
        executor = executor.crash_exitcode(crash_exitcode);
    }

    // Enable autodict if configured
    let mut tokens = Tokens::new();
    if !opt.no_autodict {
        executor = executor.autotokens(&mut tokens);
    };

    // Set a custom directory for the current Input if configured;
    // May be used to provide a ram-disk etc..
    if let Some(cur_input_dir) = &opt.cur_input_dir {
        if opt.harness_input_type.is_none() {
            return Err(Error::illegal_argument(
                "cannot use AFL_TMPDIR with stdin input type.",
            ));
        }
        executor = executor.arg_input_file(cur_input_dir.join(get_unique_std_input_file()));
    }

    // Finalize and build our Executor
    let mut executor = executor
        .build(tuple_list!(time_observer, edges_observer))
        .unwrap();

    // Load our seeds.
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs_multicore(
                &mut fuzzer,
                &mut executor,
                &mut restarting_mgr,
                &[fuzzer_dir.join("queue")],
                &core_id,
                opt.cores.as_ref().expect("invariant; should never occur"),
            )
            .unwrap_or_else(|err| panic!("Failed to load initial corpus! {err:?}"));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // We set IsInitialCorpusEntry as metadata for all initial testcases.
    // Used in Cmplog stage if AFL_CMPLOG_ONLY_NEW.
    if opt.cmplog_only_new {
        for id in state.corpus().ids() {
            let testcase = state.corpus().get(id).expect("should be present in Corpus");
            testcase
                .borrow_mut()
                .add_metadata(IsInitialCorpusEntryMetadata {});
        }
    }

    // Add the tokens to State
    state.add_metadata(tokens);

    // Set the start time of our Fuzzer
    *state.start_time_mut() = current_time();

    // Tell [`SeedFeedback`] that we're done loading seeds; rendering it benign.
    fuzzer.feedback_mut().done_loading_seeds();

    // Set LD_PRELOAD (Linux) && DYLD_INSERT_LIBRARIES (OSX) for target.
    if let Some(preload_env) = &opt.afl_preload {
        std::env::set_var("LD_PRELOAD", preload_env);
        std::env::set_var("DYLD_INSERT_LIBRARIES", preload_env);
    }

    // Create a Sync stage to sync from foreign fuzzers
    let sync_stage = IfStage::new(
        |_, _, _, _| Ok(is_main_node && !opt.foreign_sync_dirs.is_empty()),
        tuple_list!(SyncFromDiskStage::with_from_file(
            opt.foreign_sync_dirs.clone(),
            opt.foreign_sync_interval
        )),
    );

    // Create a CmpLog executor if configured.
    if let Some(ref cmplog_binary) = opt.cmplog_binary {
        // The CmpLog map shared between the CmpLog observer and CmpLog executor
        let mut cmplog_shmem = shmem_provider.uninit_on_shmem::<AFLppCmpLogMap>().unwrap();

        // Let the Forkserver know the CmpLog shared memory map ID.
        cmplog_shmem.write_to_env("__AFL_CMPLOG_SHM_ID").unwrap();
        let cmpmap = unsafe { OwnedRefMut::from_shmem(&mut cmplog_shmem) };

        // Create the CmpLog observer.
        let cmplog_observer = AFLppCmpLogObserver::new("cmplog", cmpmap, true);
        let cmplog_ref = cmplog_observer.handle();

        // Create the CmpLog executor.
        // Cmplog has 25% execution overhead so we give it double the timeout
        let cmplog_executor = base_executor(opt, &mut shmem_provider)
            .timeout(Duration::from_millis(opt.hang_timeout * 2))
            .program(cmplog_binary)
            .build(tuple_list!(cmplog_observer))
            .unwrap();

        // Create the CmpLog tracing stage.
        let tracing = AFLppCmplogTracingStage::new(cmplog_executor, cmplog_ref);

        // Create a randomic Input2State stage
        let rq = MultiMutationalStage::new(AFLppRedQueen::with_cmplog_options(true, true));

        // Create an IfStage and wrap the CmpLog stages in it.
        // We run cmplog on the second fuzz run of the testcase.
        // This stage checks if the testcase has been fuzzed more than twice, if so do not run cmplog.
        // We also check if it is an initial corpus testcase
        // and if run with AFL_CMPLOG_ONLY_NEW, then we avoid cmplog.
        let cb = |_fuzzer: &mut _,
                  _executor: &mut _,
                  state: &mut LibaflFuzzState,
                  _event_manager: &mut _|
         -> Result<bool, Error> {
            let testcase = state.current_testcase()?;
            if testcase.scheduled_count() == 1
                || (opt.cmplog_only_new && testcase.has_metadata::<IsInitialCorpusEntryMetadata>())
            {
                return Ok(false);
            }
            Ok(true)
        };
        let cmplog = IfStage::new(cb, tuple_list!(colorization, tracing, rq));

        // The order of the stages matter!
        let mut stages = tuple_list!(
            calibration,
            cmplog,
            mutational_stage,
            afl_stats_stage,
            sync_stage
        );

        // Run our fuzzer; WITH CmpLog
        run_fuzzer_with_stages(
            opt,
            &mut fuzzer,
            &mut stages,
            &mut executor,
            &mut state,
            &mut restarting_mgr,
        )?;
    } else {
        // The order of the stages matter!
        let mut stages = tuple_list!(calibration, mutational_stage, afl_stats_stage, sync_stage);

        // Run our fuzzer; NO CmpLog
        run_fuzzer_with_stages(
            opt,
            &mut fuzzer,
            &mut stages,
            &mut executor,
            &mut state,
            &mut restarting_mgr,
        )?;
    }
    Ok(())
    // TODO: serialize state when exiting.
}

fn base_executor<'a>(
    opt: &'a Opt,
    shmem_provider: &'a mut StdShMemProvider,
) -> ForkserverExecutorBuilder<'a, StdShMemProvider> {
    let mut executor = ForkserverExecutor::builder()
        .program(opt.executable.clone())
        .shmem_provider(shmem_provider)
        .coverage_map_size(opt.map_size.unwrap_or(AFL_DEFAULT_MAP_SIZE))
        .debug_child(opt.debug_child)
        .is_persistent(opt.is_persistent)
        .is_deferred_frksrv(opt.defer_forkserver)
        .min_input_size(opt.min_input_len.unwrap_or(AFL_DEFAULT_INPUT_LEN_MIN))
        .max_input_size(opt.max_input_len.unwrap_or(AFL_DEFAULT_INPUT_LEN_MAX))
        .timeout(Duration::from_millis(opt.hang_timeout));
    if let Some(target_env) = &opt.target_env {
        executor = executor.envs(target_env);
    }
    if let Some(kill_signal) = opt.kill_signal {
        executor = executor.kill_signal(kill_signal);
    }
    if let Some(harness_input_type) = &opt.harness_input_type {
        executor = executor.parse_afl_cmdline([harness_input_type]);
    }
    executor
}

pub fn fuzzer_target_mode(opt: &Opt) -> Cow<'static, str> {
    let mut res = String::new();
    if opt.unicorn_mode {
        res = format!("{res}unicorn ");
    }
    if opt.qemu_mode {
        res = format!("{res}qemu ");
    }
    if opt.forkserver_cs {
        res = format!("{res}coresight ");
    }
    if opt.no_forkserver {
        res = format!("{res}no_fsrv ");
    }
    if opt.crash_mode {
        res = format!("{res}crash ");
    }
    if opt.is_persistent {
        res = format!("{res}persistent ");
    }
    // TODO: not always shmem_testcase
    res = format!("{res}shmem_testcase ");
    if opt.defer_forkserver {
        res = format!("{res}deferred ");
    }
    if !(opt.unicorn_mode
        || opt.qemu_mode
        || opt.forkserver_cs
        || opt.non_instrumented_mode
        || opt.no_forkserver
        || opt.crash_mode
        || opt.is_persistent
        || opt.defer_forkserver)
    {
        res = format!("{res}default");
    }
    Cow::Owned(res)
}

#[derive(Debug, Serialize, Deserialize, SerdeAny)]
pub struct IsInitialCorpusEntryMetadata {}

pub fn run_fuzzer_with_stages<Z, ST, E, EM>(
    opt: &Opt,
    fuzzer: &mut Z,
    stages: &mut ST,
    executor: &mut E,
    state: &mut <Z as UsesState>::State,
    mgr: &mut EM,
) -> Result<(), Error>
where
    Z: Fuzzer<E, EM, ST>,
    E: UsesState<State = Z::State>,
    EM: ProgressReporter<State = Z::State> + EventProcessor<E, Z>,
    ST: StagesTuple<E, EM, Z::State, Z>,
    <Z as UsesState>::State: HasLastReportTime + HasExecutions + HasMetadata,
{
    if opt.bench_just_one {
        fuzzer.fuzz_loop_for(stages, executor, state, mgr, 1)?;
    } else {
        fuzzer.fuzz_loop(stages, executor, state, mgr)?;
    }
    Ok(())
}
