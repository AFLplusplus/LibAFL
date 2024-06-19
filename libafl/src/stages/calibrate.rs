//! The calibration stage. The fuzzer measures the average exec time and the bitmap size.

use alloc::{borrow::Cow, vec::Vec};
use core::{fmt::Debug, marker::PhantomData, time::Duration};

use hashbrown::HashSet;
use libafl_bolts::{current_time, impl_serdeany, tuples::Handle, AsIter, Named};
use num_traits::Bounded;
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, SchedulerTestcaseMetadata},
    events::{Event, EventFirer, LogSeverity},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::{map::MapFeedbackMetadata, HasObserverHandle},
    fuzzer::Evaluator,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
    observers::{MapObserver, ObserversTuple},
    schedulers::powersched::SchedulerMetadata,
    stages::{ExecutionCountRestartHelper, Stage},
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, UsesState},
    Error, HasMetadata, HasNamedMetadata,
};

/// The metadata to keep unstable entries
/// Formula is same as AFL++: number of unstable entries divided by the number of filled entries.
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnstableEntriesMetadata {
    unstable_entries: HashSet<usize>,
    filled_entries_count: usize,
}
impl_serdeany!(UnstableEntriesMetadata);

impl UnstableEntriesMetadata {
    #[must_use]
    /// Create a new [`struct@UnstableEntriesMetadata`]
    pub fn new() -> Self {
        Self {
            unstable_entries: HashSet::new(),
            filled_entries_count: 0,
        }
    }

    /// Getter
    #[must_use]
    pub fn unstable_entries(&self) -> &HashSet<usize> {
        &self.unstable_entries
    }

    /// Getter
    #[must_use]
    pub fn filled_entries_count(&self) -> usize {
        self.filled_entries_count
    }
}

impl Default for UnstableEntriesMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Default name for `CalibrationStage`; derived from AFL++
pub const CALIBRATION_STAGE_NAME: &str = "calibration";
/// The calibration stage will measure the average exec time and the target's stability for this input.
#[derive(Clone, Debug)]
pub struct CalibrationStage<C, E, O, OT> {
    map_observer_handle: Handle<C>,
    map_name: Cow<'static, str>,
    name: Cow<'static, str>,
    stage_max: usize,
    /// If we should track stability
    track_stability: bool,
    restart_helper: ExecutionCountRestartHelper,
    phantom: PhantomData<(E, O, OT)>,
}

const CAL_STAGE_START: usize = 4; // AFL++'s CAL_CYCLES_FAST + 1
const CAL_STAGE_MAX: usize = 8; // AFL++'s CAL_CYCLES + 1

impl<C, E, O, OT> UsesState for CalibrationStage<C, E, O, OT>
where
    E: UsesState,
{
    type State = E::State;
}

impl<C, E, EM, O, OT, Z> Stage<E, EM, Z> for CalibrationStage<C, E, O, OT>
where
    E: Executor<EM, Z> + HasObservers<Observers = OT>,
    EM: EventFirer<State = Self::State>,
    O: MapObserver,
    C: AsRef<O>,
    for<'de> <O as MapObserver>::Entry: Serialize + Deserialize<'de> + 'static,
    OT: ObserversTuple<Self::State>,
    Self::State: HasCorpus + HasMetadata + HasNamedMetadata + HasExecutions,
    Z: Evaluator<E, EM, State = Self::State>,
{
    #[inline]
    #[allow(
        clippy::let_and_return,
        clippy::too_many_lines,
        clippy::cast_precision_loss
    )]
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        mgr: &mut EM,
    ) -> Result<(), Error> {
        // Run this stage only once for each corpus entry and only if we haven't already inspected it
        {
            let testcase = state.current_testcase()?;
            // println!("calibration; corpus.scheduled_count() : {}", corpus.scheduled_count());

            if testcase.scheduled_count() > 0 {
                return Ok(());
            }
        }

        let mut iter = self.stage_max;
        // If we restarted after a timeout or crash, do less iterations.
        iter -= usize::try_from(self.restart_helper.execs_since_progress_start(state)?)?;

        let input = state.current_input_cloned()?;

        // Run once to get the initial calibration map
        executor.observers_mut().pre_exec_all(state, &input)?;

        let mut start = current_time();

        let exit_kind = executor.run_target(fuzzer, state, mgr, &input)?;
        let mut total_time = if exit_kind == ExitKind::Ok {
            current_time() - start
        } else {
            mgr.log(
                state,
                LogSeverity::Warn,
                "Corpus entry errored on execution!".into(),
            )?;
            // assume one second as default time
            Duration::from_secs(1)
        };

        executor
            .observers_mut()
            .post_exec_all(state, &input, &exit_kind)?;

        let observers = &executor.observers();
        let map_first = observers[&self.map_observer_handle].as_ref();
        let map_first_filled_count = match state
            .named_metadata_map()
            .get::<MapFeedbackMetadata<O::Entry>>(&self.map_name)
        {
            Some(metadata) => metadata.num_covered_map_indexes,
            None => map_first.count_bytes().try_into().map_err(|len| {
                Error::illegal_state(
                    format!(
                        "map's filled entry count ({}) is greater than usize::MAX ({})",
                        len,
                        usize::MAX,
                    )
                    .as_str(),
                )
            })?,
        };
        let map_first_entries = map_first.to_vec();
        let map_first_len = map_first.to_vec().len();
        let mut unstable_entries: Vec<usize> = vec![];
        // Run CAL_STAGE_START - 1 times, increase by 2 for every time a new
        // run is found to be unstable or to crash with CAL_STAGE_MAX total runs.
        let mut i = 1;
        let mut has_errors = false;

        while i < iter {
            let input = state.current_input_cloned()?;

            executor.observers_mut().pre_exec_all(state, &input)?;
            start = current_time();

            let exit_kind = executor.run_target(fuzzer, state, mgr, &input)?;
            if exit_kind != ExitKind::Ok {
                if !has_errors {
                    mgr.log(
                        state,
                        LogSeverity::Warn,
                        "Corpus entry errored on execution!".into(),
                    )?;

                    has_errors = true;
                }

                if iter < CAL_STAGE_MAX {
                    iter += 2;
                };
            };

            total_time += current_time() - start;

            executor
                .observers_mut()
                .post_exec_all(state, &input, &exit_kind)?;

            if self.track_stability {
                let map = &executor.observers()[&self.map_observer_handle]
                    .as_ref()
                    .to_vec();

                let history_map = &mut state
                    .named_metadata_map_mut()
                    .get_mut::<MapFeedbackMetadata<O::Entry>>(&self.map_name)
                    .unwrap()
                    .history_map;

                if history_map.len() < map_first_len {
                    history_map.resize(map_first_len, O::Entry::default());
                }

                for (idx, (first, (cur, history))) in map_first_entries
                    .iter()
                    .zip(map.iter().zip(history_map.iter_mut()))
                    .enumerate()
                {
                    if *first != *cur && *history != O::Entry::max_value() {
                        *history = O::Entry::max_value();
                        unstable_entries.push(idx);
                    };
                }

                if !unstable_entries.is_empty() && iter < CAL_STAGE_MAX {
                    iter += 2;
                }
            }
            i += 1;
        }

        let mut send_default_stability = false;
        let unstable_found = !unstable_entries.is_empty();
        if unstable_found {
            let metadata = state.metadata_or_insert_with(UnstableEntriesMetadata::new);

            // If we see new unstable entries executing this new corpus entries, then merge with the existing one
            for item in unstable_entries {
                metadata.unstable_entries.insert(item); // Insert newly found items
            }
            metadata.filled_entries_count = map_first_filled_count;
        } else if !state.has_metadata::<UnstableEntriesMetadata>() {
            send_default_stability = true;
            state.add_metadata(UnstableEntriesMetadata::new());
        }

        // If weighted scheduler or powerscheduler is used, update it
        if state.has_metadata::<SchedulerMetadata>() {
            let observers = executor.observers();
            let map = observers[&self.map_observer_handle].as_ref();

            let mut bitmap_size = map.count_bytes();
            assert!(bitmap_size != 0);
            bitmap_size = bitmap_size.max(1); // just don't make it 0 because we take log2 of it later.
            let psmeta = state
                .metadata_map_mut()
                .get_mut::<SchedulerMetadata>()
                .unwrap();
            let handicap = psmeta.queue_cycles();

            psmeta.set_exec_time(psmeta.exec_time() + total_time);
            psmeta.set_cycles(psmeta.cycles() + (iter as u64));
            psmeta.set_bitmap_size(psmeta.bitmap_size() + bitmap_size);
            psmeta.set_bitmap_size_log(psmeta.bitmap_size_log() + libm::log2(bitmap_size as f64));
            psmeta.set_bitmap_entries(psmeta.bitmap_entries() + 1);

            let mut testcase = state.current_testcase_mut()?;

            testcase.set_exec_time(total_time / (iter as u32));
            // log::trace!("time: {:#?}", testcase.exec_time());

            // If the testcase doesn't have its own `SchedulerTestcaseMetadata`, create it.
            let data = if let Ok(metadata) = testcase.metadata_mut::<SchedulerTestcaseMetadata>() {
                metadata
            } else {
                let depth = if let Some(parent_id) = testcase.parent_id() {
                    if let Some(parent_metadata) = (*state.corpus().get(parent_id)?)
                        .borrow()
                        .metadata_map()
                        .get::<SchedulerTestcaseMetadata>()
                    {
                        parent_metadata.depth() + 1
                    } else {
                        0
                    }
                } else {
                    0
                };
                testcase.add_metadata(SchedulerTestcaseMetadata::new(depth));
                testcase
                    .metadata_mut::<SchedulerTestcaseMetadata>()
                    .unwrap()
            };

            data.set_cycle_and_time((total_time, iter));
            data.set_bitmap_size(bitmap_size);
            data.set_handicap(handicap);
        }

        // Send the stability event to the broker
        if unstable_found {
            if let Some(meta) = state.metadata_map().get::<UnstableEntriesMetadata>() {
                let unstable_entries = meta.unstable_entries().len();
                debug_assert_ne!(
                    map_first_filled_count, 0,
                    "The map's filled count must never be 0"
                );
                mgr.fire(
                    state,
                    Event::UpdateUserStats {
                        name: Cow::from("stability"),
                        value: UserStats::new(
                            UserStatsValue::Ratio(
                                (map_first_filled_count - unstable_entries) as u64,
                                map_first_filled_count as u64,
                            ),
                            AggregatorOps::Avg,
                        ),
                        phantom: PhantomData,
                    },
                )?;
            }
        } else if send_default_stability {
            mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: Cow::from("stability"),
                    value: UserStats::new(
                        UserStatsValue::Ratio(
                            map_first_filled_count as u64,
                            map_first_filled_count as u64,
                        ),
                        AggregatorOps::Avg,
                    ),
                    phantom: PhantomData,
                },
            )?;
        }

        Ok(())
    }

    fn restart_progress_should_run(&mut self, state: &mut Self::State) -> Result<bool, Error> {
        // TODO: Make sure this is the correct way / there may be a better way?
        self.restart_helper.restart_progress_should_run(state)
    }

    fn clear_restart_progress(&mut self, state: &mut Self::State) -> Result<(), Error> {
        // TODO: Make sure this is the correct way / there may be a better way?
        self.restart_helper.clear_restart_progress(state)
    }
}

impl<C, E, O, OT> CalibrationStage<C, E, O, OT>
where
    O: MapObserver,
    for<'it> O: AsIter<'it, Item = O::Entry>,
    C: AsRef<O>,
    OT: ObserversTuple<<Self as UsesState>::State>,
    E: UsesState,
{
    /// Create a new [`CalibrationStage`].
    #[must_use]
    pub fn new<F>(map_feedback: &F) -> Self
    where
        F: HasObserverHandle<Observer = C> + Named,
    {
        Self {
            map_observer_handle: map_feedback.observer_handle().clone(),
            map_name: map_feedback.name().clone(),
            stage_max: CAL_STAGE_START,
            track_stability: true,
            restart_helper: ExecutionCountRestartHelper::default(),
            phantom: PhantomData,
            name: Cow::Borrowed(CALIBRATION_STAGE_NAME),
        }
    }

    /// Create a new [`CalibrationStage`], but without checking stability.
    #[must_use]
    pub fn ignore_stability<F>(map_feedback: &F) -> Self
    where
        F: HasObserverHandle<Observer = C> + Named,
    {
        Self {
            map_observer_handle: map_feedback.observer_handle().clone(),
            map_name: map_feedback.name().clone(),
            stage_max: CAL_STAGE_START,
            track_stability: false,
            restart_helper: ExecutionCountRestartHelper::default(),
            phantom: PhantomData,
            name: Cow::Borrowed(CALIBRATION_STAGE_NAME),
        }
    }
}

impl<C, E, O, OT> Named for CalibrationStage<C, E, O, OT> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
