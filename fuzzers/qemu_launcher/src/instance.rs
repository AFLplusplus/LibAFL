use core::{fmt::Debug, ptr::addr_of_mut};
use std::{marker::PhantomData, process};

#[cfg(feature = "simplemgr")]
use libafl::events::SimpleEventManager;
#[cfg(not(feature = "simplemgr"))]
use libafl::events::{LlmpRestartingEventManager, MonitorTypedEventManager};
use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::EventRestarter,
    executors::ShadowExecutor,
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::Monitor,
    mutators::{
        scheduled::havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations,
        StdMOptMutator, StdScheduledMutator, Tokens,
    },
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, ShadowTracingStage,
        StagesTuple, StdMutationalStage,
    },
    state::{HasCorpus, HasMetadata, StdState, UsesState},
    Error,
};
#[cfg(not(feature = "simplemgr"))]
use libafl_bolts::shmem::StdShMemProvider;
use libafl_bolts::{
    core_affinity::CoreId,
    current_nanos,
    rands::StdRand,
    tuples::{tuple_list, Merge},
};
use libafl_qemu::{
    cmplog::CmpLogObserver,
    edges::{edges_map_mut_slice, MAX_EDGES_NUM},
    helper::QemuHelperTuple,
    Emulator, QemuExecutor, QemuHooks,
};
use typed_builder::TypedBuilder;

use crate::{harness::Harness, options::FuzzerOptions};

pub type ClientState =
    StdState<BytesInput, InMemoryOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>;

#[cfg(feature = "simplemgr")]
pub type ClientMgr<M> = SimpleEventManager<M, ClientState>;
#[cfg(not(feature = "simplemgr"))]
pub type ClientMgr<M> =
    MonitorTypedEventManager<LlmpRestartingEventManager<(), ClientState, StdShMemProvider>, M>;

#[derive(TypedBuilder)]
pub struct Instance<'a, M: Monitor> {
    options: &'a FuzzerOptions,
    emu: &'a Emulator,
    mgr: ClientMgr<M>,
    core_id: CoreId,
    extra_tokens: Option<Vec<String>>,
    #[builder(default=PhantomData)]
    phantom: PhantomData<M>,
}

impl<'a, M: Monitor> Instance<'a, M> {
    pub fn run<QT>(&mut self, helpers: QT, state: Option<ClientState>) -> Result<(), Error>
    where
        QT: QemuHelperTuple<ClientState> + Debug,
    {
        let mut hooks = QemuHooks::new(self.emu.clone(), helpers);

        // Create an observation channel using the coverage map
        let edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                edges_map_mut_slice(),
                addr_of_mut!(MAX_EDGES_NUM),
            ))
        };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

        let calibration = CalibrationStage::new(&map_feedback);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            map_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // // If not restarting, create a State from scratch
        let mut state = match state {
            Some(x) => x,
            None => {
                StdState::new(
                    // RNG
                    StdRand::with_seed(current_nanos()),
                    // Corpus that will be evolved, we keep it in memory for performance
                    InMemoryOnDiskCorpus::no_meta(self.options.queue_dir(self.core_id))?,
                    // Corpus in which we store solutions (crashes in this example),
                    // on disk so the user can get them after stopping the fuzzer
                    OnDiskCorpus::new(self.options.crashes_dir(self.core_id))?,
                    // States of the feedbacks.
                    // The feedbacks can report the data that should persist in the State.
                    &mut feedback,
                    // Same for objective feedbacks
                    &mut objective,
                )?
            }
        };

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(
            &mut state,
            &edges_observer,
            PowerSchedule::FAST,
        ));

        let observers = tuple_list!(edges_observer, time_observer);

        let mut tokens = Tokens::new();

        if let Some(extra_tokens) = &self.extra_tokens {
            for token in extra_tokens {
                let bytes = token.as_bytes().to_vec();
                let _ = tokens.add_token(&bytes);
            }
        }

        if let Some(tokenfile) = &self.options.tokens {
            tokens.add_from_file(tokenfile)?;
        }

        state.add_metadata(tokens);

        let harness = Harness::new(self.emu)?;
        let mut harness = |input: &BytesInput| harness.run(input);

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        if self.options.is_cmplog_core(self.core_id) {
            // Create a QEMU in-process executor
            let executor = QemuExecutor::new(
                &mut hooks,
                &mut harness,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            // Create an observation channel using cmplog map
            let cmplog_observer = CmpLogObserver::new("cmplog", true);

            let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

            let tracing = ShadowTracingStage::new(&mut executor);

            // Setup a randomic Input2State stage
            let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(
                I2SRandReplace::new()
            )));

            // Setup a MOPT mutator
            let mutator = StdMOptMutator::new(
                &mut state,
                havoc_mutations().merge(tokens_mutations()),
                7,
                5,
            )?;

            let power = StdPowerMutationalStage::new(mutator);

            // The order of the stages matter!
            let mut stages = tuple_list!(calibration, tracing, i2s, power);

            self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
        } else {
            // Create a QEMU in-process executor
            let mut executor = QemuExecutor::new(
                &mut hooks,
                &mut harness,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            // Setup an havoc mutator with a mutational stage
            let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            self.fuzz(&mut state, &mut fuzzer, &mut executor, &mut stages)
        }
    }

    fn fuzz<Z, E, ST>(
        &mut self,
        state: &mut ClientState,
        fuzzer: &mut Z,
        executor: &mut E,
        stages: &mut ST,
    ) -> Result<(), Error>
    where
        Z: Fuzzer<E, ClientMgr<M>, ST>
            + UsesState<State = ClientState>
            + Evaluator<E, ClientMgr<M>, State = ClientState>,
        E: UsesState<State = ClientState>,
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
