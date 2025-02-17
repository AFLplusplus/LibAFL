use core::fmt::Debug;
use std::{fs, marker::PhantomData, ops::Range, process};

#[cfg(feature = "simplemgr")]
use libafl::events::SimpleEventManager;
#[cfg(not(feature = "simplemgr"))]
use libafl::events::{LlmpRestartingEventManager, MonitorTypedEventManager};
use libafl::{
    corpus::{Corpus, HasCurrentCorpusId, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{ClientDescription, EventRestarter},
    executors::{Executor, ExitKind, ShadowExecutor},
    feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    inputs::{BytesInput, Input},
    monitors::Monitor,
    mutators::{
        havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations, StdMOptMutator,
        StdScheduledMutator, Tokens,
    },
    observers::{
        CanTrack, HitcountsMapObserver, ObserversTuple, TimeObserver, VariableMapObserver,
    },
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, AflStatsStage, IfStage,
        ShadowTracingStage, StagesTuple, StdMutationalStage,
    },
    state::{HasCorpus, HasExecutions, HasSolutions, StdState},
    Error, HasMetadata,
};
#[cfg(not(feature = "simplemgr"))]
use libafl_bolts::shmem::{StdShMem, StdShMemProvider};
use libafl_bolts::{
    ownedref::OwnedMutSlice,
    rands::StdRand,
    tuples::{tuple_list, MatchFirstType, Merge, Prepend},
};
use libafl_qemu::{
    elf::EasyElf,
    modules::{
        cmplog::CmpLogObserver,
        edges::EdgeCoverageFullVariant,
        utils::filters::{HasAddressFilter, NopPageFilter, StdAddressFilter},
        EdgeCoverageModule, EmulatorModuleTuple, SnapshotModule, StdEdgeCoverageModule,
    },
    Emulator, GuestAddr, Qemu, QemuExecutor,
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
use typed_builder::TypedBuilder;

use crate::{harness::Harness, options::FuzzerOptions};

pub type ClientState =
    StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;

#[cfg(feature = "simplemgr")]
pub type ClientMgr<M> = SimpleEventManager<BytesInput, M, ClientState>;
#[cfg(not(feature = "simplemgr"))]
pub type ClientMgr<M> = MonitorTypedEventManager<
    LlmpRestartingEventManager<(), BytesInput, ClientState, StdShMem, StdShMemProvider>,
    M,
>;

/*
 * The snapshot and iterations options interact as follows:
 *
 * +----------+------------+-------------------------------------------+
 * | snapshot | iterations | Functionality                             |
 * +----------+------------+-------------------------------------------+
 * |    N     |     N      | We set the snapshot module into manual    |
 * |          |            | mode and never reset it.                  |
 * +----------+------------+-------------------------------------------+
 * |    N     |     Y      | We set the snapshot module into manual    |
 * |          |            | mode and never reset it.                  |
 * +----------+------------+-------------------------------------------+
 * |    Y     |     N      | We set the snapshot module into automatic |
 * |          |            | mode so it resets after every iteration.  |
 * +----------+------------+-------------------------------------------+
 * |    Y     |     Y      | We set the snapshot module into manual    |
 * |          |            | mode and manually reset it after the      |
 * |          |            | required number of iterations are done.   |
 * +----------+------------+-------------------------------------------+
 */

#[derive(TypedBuilder)]
pub struct Instance<'a, M: Monitor> {
    options: &'a FuzzerOptions,
    mgr: ClientMgr<M>,
    client_description: ClientDescription,
    #[builder(default)]
    extra_tokens: Vec<String>,
    #[builder(default=PhantomData)]
    phantom: PhantomData<M>,
}

impl<M: Monitor> Instance<'_, M> {
    fn coverage_filter(&self, qemu: Qemu) -> Result<StdAddressFilter, Error> {
        /* Conversion is required on 32-bit targets, but not on 64-bit ones */
        if let Some(includes) = &self.options.include {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
            let rules = includes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(StdAddressFilter::allow_list(rules))
        } else if let Some(excludes) = &self.options.exclude {
            #[cfg_attr(target_pointer_width = "64", allow(clippy::useless_conversion))]
            let rules = excludes
                .iter()
                .map(|x| Range {
                    start: x.start.into(),
                    end: x.end.into(),
                })
                .collect::<Vec<Range<GuestAddr>>>();
            Ok(StdAddressFilter::deny_list(rules))
        } else {
            let mut elf_buffer = Vec::new();
            let elf = EasyElf::from_file(qemu.binary_path(), &mut elf_buffer)?;
            let range = elf
                .get_section(".text", qemu.load_addr())
                .ok_or_else(|| Error::key_not_found("Failed to find .text section"))?;
            Ok(StdAddressFilter::allow_list(vec![range]))
        }
    }

    #[expect(clippy::too_many_lines)]
    pub fn run<ET>(
        &mut self,
        args: Vec<String>,
        modules: ET,
        state: Option<ClientState>,
    ) -> Result<(), Error>
    where
        ET: EmulatorModuleTuple<BytesInput, ClientState> + Debug,
    {
        // Create an observation channel using the coverage map
        let mut edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
                &raw mut MAX_EDGES_FOUND,
            ))
            .track_indices()
        };

        let edge_coverage_module = StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()?;

        let mut snapshot_module = SnapshotModule::new();

        /*
         * Since the generics for the modules are already excessive when taking
         * into accout asan, asan guest mode, cmplog, and injection, we will
         * always include the SnapshotModule in all configurations, but simply
         * not use it when it is not required. See the table at the top of this
         * file for details.
         */
        if !self.options.snapshots || self.options.iterations.is_some() {
            snapshot_module.use_manual_reset();
        }

        let modules = modules
            .prepend(edge_coverage_module)
            .prepend(snapshot_module);
        let mut emulator = Emulator::empty()
            .qemu_parameters(args)
            .modules(modules)
            .build()?;
        let harness = Harness::init(emulator.qemu()).expect("Error setting up harness.");
        let qemu = emulator.qemu();

        // update address filter after qemu has been initialized
        emulator.modules_mut()
            .modules_mut()
            .match_first_type_mut::<EdgeCoverageModule<StdAddressFilter, NopPageFilter, EdgeCoverageFullVariant, false, 0>>()
            .expect("Could not find back the edge module").update_address_filter(qemu, self.coverage_filter(qemu)?);

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::with_name("map_feedback", &edges_observer);
        let map_objective = MaxMapFeedback::with_name("map_objective", &edges_observer);

        let calibration = CalibrationStage::new(&map_feedback);
        let calibration_cmplog = CalibrationStage::new(&map_feedback);

        let stats_stage = IfStage::new(
            |_, _, _, _| Ok(self.options.tui),
            tuple_list!(AflStatsStage::builder()
                .map_observer(&edges_observer)
                .build()?),
        );
        let stats_stage_cmplog = IfStage::new(
            |_, _, _, _| Ok(self.options.tui),
            tuple_list!(AflStatsStage::builder()
                .map_observer(&edges_observer)
                .build()?),
        );

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            map_feedback,
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_and_fast!(
            feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new()),
            map_objective
        );

        // // If not restarting, create a State from scratch
        let mut state = match state {
            Some(x) => x,
            None => {
                StdState::new(
                    // RNG
                    StdRand::new(),
                    // Corpus that will be evolved, we keep it in memory for performance
                    InMemoryOnDiskCorpus::no_meta(
                        self.options.queue_dir(self.client_description.clone()),
                    )?,
                    // Corpus in which we store solutions (crashes in this example),
                    // on disk so the user can get them after stopping the fuzzer
                    OnDiskCorpus::new(self.options.crashes_dir(self.client_description.clone()))?,
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
            &edges_observer,
            PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
        );

        let observers = tuple_list!(edges_observer, time_observer);

        let mut tokens = Tokens::new();

        for token in &self.extra_tokens {
            let bytes = token.as_bytes().to_vec();
            let _ = tokens.add_token(&bytes);
        }

        if let Some(tokenfile) = &self.options.tokens {
            tokens.add_from_file(tokenfile)?;
        }

        state.add_metadata(tokens);

        harness.post_fork();

        let mut harness = |_emulator: &mut Emulator<_, _, _, _, _, _, _>,
                           _state: &mut _,
                           input: &BytesInput| harness.run(input);

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        if let Some(rerun_input) = &self.options.rerun_input {
            // TODO: We might want to support non-bytes inputs at some point?
            let bytes = fs::read(rerun_input)
                .unwrap_or_else(|_| panic!("Could not load file {rerun_input:?}"));
            let input = BytesInput::new(bytes);

            let mut executor = QemuExecutor::new(
                emulator,
                &mut harness,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            executor
                .run_target(&mut fuzzer, &mut state, &mut self.mgr, &input)
                .expect("Error running target");
            // We're done :)
            process::exit(0);
        }

        if self
            .options
            .is_cmplog_core(self.client_description.core_id())
        {
            // Create a QEMU in-process executor
            let executor = QemuExecutor::new(
                emulator,
                &mut harness,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            // Create an observation channel using cmplog map
            let cmplog_observer = CmpLogObserver::new("cmplog", true);

            let mut shadow_executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

            let tracing = ShadowTracingStage::new(&mut shadow_executor);

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

            let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
                StdPowerMutationalStage::new(mutator);

            // The order of the stages matter!
            let mut stages =
                tuple_list!(calibration_cmplog, tracing, i2s, power, stats_stage_cmplog);

            self.fuzz(
                &mut state,
                &mut fuzzer,
                &mut shadow_executor,
                Self::reset_shadow_executor_snapshot_module,
                qemu,
                &mut stages,
            )
        } else {
            // Create a QEMU in-process executor
            let mut executor = QemuExecutor::new(
                emulator,
                &mut harness,
                observers,
                &mut fuzzer,
                &mut state,
                &mut self.mgr,
                self.options.timeout,
            )?;

            // Setup an havoc mutator with a mutational stage
            let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));
            let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
                StdPowerMutationalStage::new(mutator);
            let mut stages = tuple_list!(calibration, power, stats_stage);

            self.fuzz(
                &mut state,
                &mut fuzzer,
                &mut executor,
                Self::reset_executor_snapshot_module,
                qemu,
                &mut stages,
            )
        }
    }

    fn reset_executor_snapshot_module<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, Z>(
        executor: &mut QemuExecutor<'a, C, CM, ED, EM, (SnapshotModule, ET), H, I, OT, S, SM, Z>,
        qemu: Qemu,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        H: for<'e, 's, 'i> FnMut(
            &'e mut Emulator<C, CM, ED, (SnapshotModule, ET), I, S, SM>,
            &'s mut S,
            &'i I,
        ) -> ExitKind,
        I: Input + Unpin,
        OT: ObserversTuple<I, S>,
        S: HasCorpus<I> + HasCurrentCorpusId + HasSolutions<I> + HasExecutions + Unpin,
    {
        executor
            .inner_mut()
            .exposed_executor_state_mut()
            .modules_mut()
            .modules_mut()
            .0
            .reset(qemu);
    }

    fn reset_shadow_executor_snapshot_module<'a, C, CM, ED, EM, ET, H, I, OT, S, SM, SOT, Z>(
        executor: &mut ShadowExecutor<
            QemuExecutor<'a, C, CM, ED, EM, (SnapshotModule, ET), H, I, OT, S, SM, Z>,
            I,
            S,
            SOT,
        >,
        qemu: Qemu,
    ) where
        ET: EmulatorModuleTuple<I, S>,
        H: for<'e, 's, 'i> FnMut(
            &'e mut Emulator<C, CM, ED, (SnapshotModule, ET), I, S, SM>,
            &'s mut S,
            &'i I,
        ) -> ExitKind,
        I: Input + Unpin,
        OT: ObserversTuple<I, S>,
        S: HasCorpus<I> + HasCurrentCorpusId + HasSolutions<I> + HasExecutions + Unpin,
        SOT: ObserversTuple<I, S>,
    {
        executor
            .executor_mut()
            .inner_mut()
            .exposed_executor_state_mut()
            .modules_mut()
            .modules_mut()
            .0
            .reset(qemu);
    }

    fn fuzz<Z, E, RSM, ST>(
        &mut self,
        state: &mut ClientState,
        fuzzer: &mut Z,
        executor: &mut E,
        reset_snapshot_module: RSM,
        qemu: Qemu,
        stages: &mut ST,
    ) -> Result<(), Error>
    where
        ST: StagesTuple<E, ClientMgr<M>, ClientState, Z>,
        RSM: Fn(&mut E, Qemu),
        Z: Fuzzer<E, ClientMgr<M>, BytesInput, ClientState, ST>
            + Evaluator<E, ClientMgr<M>, BytesInput, ClientState>,
    {
        if state.must_load_initial_inputs() {
            let corpus_dirs = [self.options.input_dir()];

            state
                .load_initial_inputs(fuzzer, executor, &mut self.mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {corpus_dirs:?}");
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        /*
         * See the table a the top of this file for details on how the snapshot
         * and iterations options interact.
         */
        if let Some(iters) = self.options.iterations {
            if self.options.snapshots {
                loop {
                    reset_snapshot_module(executor, qemu);
                    fuzzer.fuzz_loop_for(stages, executor, state, &mut self.mgr, iters)?;
                }
            } else {
                fuzzer.fuzz_loop_for(stages, executor, state, &mut self.mgr, iters)?;

                // It's important, that we store the state before restarting!
                // Else, the parent will not respawn a new child and quit.
                self.mgr.on_restart(state)?;
            }
        } else {
            fuzzer.fuzz_loop(stages, executor, state, &mut self.mgr)?;
        }

        Ok(())
    }
}
