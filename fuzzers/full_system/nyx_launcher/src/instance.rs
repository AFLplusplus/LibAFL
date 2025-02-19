use std::{marker::PhantomData, process};

use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{
        ClientDescription, EventRestarter, LlmpRestartingEventManager, MonitorTypedEventManager,
        NopEventManager,
    },
    executors::{Executor, ShadowExecutor},
    feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::Monitor,
    mutators::{
        havoc_mutations, tokens_mutations, I2SRandReplace, StdMOptMutator, StdScheduledMutator,
        Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        power::StdPowerMutationalStage, CalibrationStage, ShadowTracingStage, StagesTuple,
        StdMutationalStage,
    },
    state::{HasCorpus, HasMaxSize, StdState},
    Error, HasMetadata, NopFuzzer,
};
use libafl_bolts::{
    current_nanos,
    rands::StdRand,
    shmem::{StdShMem, StdShMemProvider},
    tuples::{tuple_list, Merge},
};
use libafl_nyx::{
    cmplog::NyxCmpObserver, executor::NyxExecutor, helper::NyxHelper, settings::NyxSettings,
};
use typed_builder::TypedBuilder;

use crate::options::FuzzerOptions;

pub type ClientState =
    StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

pub type ClientMgr<M> = MonitorTypedEventManager<
    LlmpRestartingEventManager<(), BytesInput, ClientState, StdShMem, StdShMemProvider>,
    M,
>;

#[derive(TypedBuilder)]
pub struct Instance<'a, M: Monitor> {
    options: &'a FuzzerOptions,
    /// The harness. We create it before forking, then `take()` it inside the client.
    mgr: ClientMgr<M>,
    client_description: ClientDescription,
    #[builder(default=PhantomData)]
    phantom: PhantomData<M>,
}

impl<M: Monitor> Instance<'_, M> {
    pub fn run(mut self, state: Option<ClientState>) -> Result<(), Error> {
        let parent_cpu_id = self
            .options
            .cores
            .ids
            .first()
            .expect("unable to get first core id");

        let settings = NyxSettings::builder()
            .cpu_id(self.client_description.core_id().0)
            .parent_cpu_id(Some(parent_cpu_id.0))
            .input_buffer_size(self.options.buffer_size)
            .timeout_secs(0)
            .timeout_micro_secs(self.options.timeout)
            .build();

        let helper = NyxHelper::new(self.options.shared_dir(), settings)?;

        let trace_observer = HitcountsMapObserver::new(unsafe {
            StdMapObserver::from_mut_ptr("trace", helper.bitmap_buffer, helper.bitmap_size)
        })
        .track_indices();

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::new(&trace_observer);

        // let stdout_observer = StdOutObserver::new("hprintf_output");

        let calibration = CalibrationStage::new(&map_feedback);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            map_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer),
            // Append stdout to metadata
            // StdOutToMetadataFeedback::new(&stdout_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_and_fast!(
            // CrashFeedback::new(),
            feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new()),
            // Take it only if trigger new coverage over crashes
            // For deduplication
            MaxMapFeedback::with_name("mapfeedback_metadata_objective", &trace_observer)
        );

        // If not restarting, create a State from scratch
        let mut state = match state {
            Some(x) => x,
            None => {
                StdState::new(
                    // RNG
                    StdRand::with_seed(current_nanos()),
                    // Corpus that will be evolved, we keep it in memory for performance
                    InMemoryOnDiskCorpus::no_meta(
                        self.options.queue_dir(self.client_description.core_id()),
                    )?,
                    // Corpus in which we store solutions (crashes in this example),
                    // on disk so the user can get them after stopping the fuzzer
                    OnDiskCorpus::new(self.options.crashes_dir(self.client_description.core_id()))?,
                    // States of the feedbacks.
                    // The feedbacks can report the data that should persist in the State.
                    &mut feedback,
                    // Same for objective feedbacks
                    &mut objective,
                )?
            }
        };

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(
            &trace_observer,
            PowerQueueScheduler::new(&mut state, &trace_observer, PowerSchedule::fast()),
        );

        let observers = tuple_list!(trace_observer, time_observer); // stdout_observer);

        let mut tokens = Tokens::new();

        if let Some(tokenfile) = &self.options.tokens {
            tokens.add_from_file(tokenfile)?;
        }

        state.add_metadata(tokens);

        state.set_max_size(self.options.buffer_size);

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        if let Some(rerun_input) = &self.options.rerun_input {
            // TODO: We might want to support non-bytes inputs at some point?
            let bytes = std::fs::read(rerun_input)
                .unwrap_or_else(|_| panic!("Could not load file {rerun_input:?}"));
            let input = BytesInput::new(bytes);

            let mut executor = NyxExecutor::builder().build(helper, observers);

            let exit_kind = executor
                .run_target(
                    &mut NopFuzzer::new(),
                    &mut state,
                    &mut NopEventManager::new(),
                    &input,
                )
                .expect("Error running target");
            println!("Rerun finished with ExitKind {:?}", exit_kind);
            // We're done :)
            process::exit(0);
        }

        if self
            .options
            .is_cmplog_core(self.client_description.core_id())
        {
            let cmplog_observer = NyxCmpObserver::new("cmplog", helper.redqueen_path.clone(), true);

            let executor = NyxExecutor::builder().build(helper, observers);

            // Show the cmplog observer
            let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

            // Setup a randomic Input2State stage
            let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
                I2SRandReplace::new()
            )));

            let tracing = ShadowTracingStage::new(&mut executor);

            // Setup a MOPT mutator
            let mutator = StdMOptMutator::new(
                &mut state,
                havoc_mutations().merge(tokens_mutations()),
                7,
                5,
            )?;

            let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
                StdPowerMutationalStage::new(mutator);

            // The order of the stages matter!
            let mut stages = tuple_list!(calibration, tracing, i2s, power);

            return self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages);
        }

        let mut executor = NyxExecutor::builder().build(helper, observers);

        // Setup an havoc mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
    }

    fn fuzz<Z, E, ST>(
        &mut self,
        state: &mut ClientState,
        fuzzer: &mut Z,
        executor: &mut E,
        stages: &mut ST,
    ) -> Result<(), Error>
    where
        Z: Fuzzer<E, ClientMgr<M>, BytesInput, ClientState, ST>
            + Evaluator<E, ClientMgr<M>, BytesInput, ClientState>,
        ST: StagesTuple<E, ClientMgr<M>, ClientState, Z>,
    {
        let corpus_dirs = [self.options.input_dir()];

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(fuzzer, executor, &mut self.mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {corpus_dirs:?}");
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        if let Some(iters) = self.options.iterations {
            fuzzer.fuzz_loop_for(stages, executor, state, &mut self.mgr, iters)?;

            // It's important, that we store the state before restarting!
            // Else, the parent will not respawn a new child and quit.
            self.mgr.on_restart(state)?;
        } else {
            fuzzer.fuzz_loop(stages, executor, state, &mut self.mgr)?;
        }

        Ok(())
    }
}
