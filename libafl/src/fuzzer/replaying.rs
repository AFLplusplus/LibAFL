//! Replaying input to ensure evaluation consistency

use crate::{
    events::{Event, EventFirer},
    executors::{Executor, ExitKind, HasObservers},
    fuzzer::ExecutesInput,
    mark_feature_time,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
    observers::ObserversTuple,
    start_timer,
};
use alloc::borrow::Cow;
use core::{hash::Hash, marker::PhantomData};
use hashbrown::HashMap;
use libafl_bolts::{
    generic_hash_std,
    tuples::{Handle, MatchNameRef},
    Error,
};

/// Helper trait until [`ExecutesInput`] no longer requires the fuzzer to be passed.
///
/// See <https://github.com/AFLplusplus/LibAFL/issues/2880>
pub trait WrappedExecutesInput<F, E, EM, I, S> {
    /// Evaluate the input
    fn wrapped_execute_input(
        &self,
        fuzzer: &mut F,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error>;
}

/// Evaluate the input only once
#[derive(Debug, Clone)]
pub struct NoReplayingConfig;

impl<F, E, EM, I, S> WrappedExecutesInput<F, E, EM, I, S> for NoReplayingConfig
where
    F: ExecutesInput<E, EM, I, S>,
    E: Executor<EM, I, S, F> + HasObservers,
    E::Observers: ObserversTuple<I, S>,
{
    #[inline]
    fn wrapped_execute_input(
        &self,
        fuzzer: &mut F,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        start_timer!(state);
        executor.observers_mut().pre_exec_all(state, input)?;
        mark_feature_time!(state, PerfFeature::PreExecObservers);

        start_timer!(state);
        let exit_kind = executor.run_target(fuzzer, state, event_mgr, input)?;
        mark_feature_time!(state, PerfFeature::TargetExecution);

        start_timer!(state);
        executor
            .observers_mut()
            .post_exec_all(state, input, &exit_kind)?;

        mark_feature_time!(state, PerfFeature::PostExecObservers);
        Ok(exit_kind)
    }
}

/// Runs the evaluation multiple times to ensure consistency
///
/// The input will be evaluated as often as necessary until the most frequent result appears
/// - at least `min_count_diff` times
/// - at least `min_count_diff` times more often than any other result
/// - at least `min_factor_diff` times more often than any other result
/// - at most `max_trys` times
///
/// If `max_trys` is hit, the last observer values are left in place and the most frequent [`ExitKind`] is returned.
/// If `ignore_inconsistent_inputs` is set, [`ExitKind::Inconsistent`] is reported and the input is added to neighter the corpus nor the solutions.
#[derive(Debug, Clone)]
pub struct ReplayingConfig<O> {
    min_count_diff: u32,
    min_factor_diff: f64,
    max_trys: u32,
    ignore_inconsistent_inputs: bool,
    observer: Handle<O>,
}

impl<O> ReplayingConfig<O> {
    /// Create a new [`ReplayingConfig`]
    #[must_use]
    #[inline]
    pub fn new(
        min_count_diff: u32,
        min_factor_diff: f64,
        max_trys: u32,
        ignore_inconsistent_inputs: bool,
        observer: Handle<O>,
    ) -> Self {
        Self {
            min_count_diff,
            min_factor_diff,
            max_trys,
            ignore_inconsistent_inputs,
            observer,
        }
    }
}

impl<F, E, EM, I, O, S> WrappedExecutesInput<F, E, EM, I, S> for ReplayingConfig<O>
where
    F: ExecutesInput<E, EM, I, S>,
    E: Executor<EM, I, S, F> + HasObservers,
    E::Observers: ObserversTuple<I, S>,
    O: Hash,
    EM: EventFirer<I, S>,
{
    #[inline]
    fn wrapped_execute_input(
        &self,
        fuzzer: &mut F,
        state: &mut S,
        executor: &mut E,
        event_mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let mut results = HashMap::new();
        let mut inconsistent = 0;
        let (exit_kind, total_replayed) = loop {
            let exit_kind = NoReplayingConfig
                .wrapped_execute_input(fuzzer, state, executor, event_mgr, input)?;
            let observers = executor.observers();

            let observer = observers
                .get(&self.observer)
                .expect("Observer to track consistency of not found");
            let hash = generic_hash_std(observer);
            *results.entry((hash, exit_kind)).or_insert(0_u32) += 1;

            let total_replayed = results.values().sum::<u32>();

            let ((max_hash, max_exit_kind), max_count) =
                results.iter().max_by(|(_, a), (_, b)| a.cmp(b)).unwrap();

            if *max_count < self.min_count_diff {
                continue; // require at least min_count_diff replays
            }

            let consistent_enough = results
                .values()
                .filter(|e| **e != *max_count)
                .all(|&count| {
                    let min_value_count = count + self.min_count_diff;
                    let min_value_factor = f64::from(count) * self.min_factor_diff;
                    min_value_count <= *max_count && min_value_factor <= f64::from(*max_count)
                });

            let latest_execution_is_dominant = hash == *max_hash && exit_kind == *max_exit_kind;

            if consistent_enough && latest_execution_is_dominant {
                break (exit_kind, total_replayed);
            } else if total_replayed >= self.max_trys {
                log::warn!(
                            "Replaying {} times did not lead to dominant result, using the latest observer value and most common exit_kind. Details: {results:?}",
                            total_replayed
                        );
                inconsistent = 1;
                let returned_exit_kind = if self.ignore_inconsistent_inputs {
                    ExitKind::Inconsistent
                } else {
                    *max_exit_kind
                };
                break (returned_exit_kind, total_replayed);
            }
        };

        event_mgr.fire(
            state,
            Event::UpdateUserStats {
                name: Cow::Borrowed("consistency-caused-replay-per-input"),
                value: UserStats::new(
                    UserStatsValue::Float(total_replayed.into()),
                    AggregatorOps::Avg,
                ),
                phantom: PhantomData,
            },
        )?;

        event_mgr.fire(
            state,
            Event::UpdateUserStats {
                name: Cow::Borrowed("uncaptured-inconsistent-rate"),
                value: UserStats::new(
                    UserStatsValue::Float(u32::try_from(inconsistent).unwrap().into()),
                    AggregatorOps::Avg,
                ),
                phantom: PhantomData,
            },
        )?;
        Ok(exit_kind)
    }
}

#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use core::cell::RefCell;

    use libafl_bolts::{
        rands::StdRand,
        tuples::{tuple_list, Handled},
    };

    use crate::{
        corpus::{Corpus as _, InMemoryCorpus},
        events::NopEventManager,
        executors::{ExitKind, InProcessExecutor},
        filter::NopInputFilter,
        fuzzer::{replaying::ReplayingConfig, ExecutesInput},
        inputs::ValueInput,
        observers::StdMapObserver,
        schedulers::StdScheduler,
        state::{HasCorpus, HasSolutions, StdState},
        StdFuzzer,
    };

    #[test]
    fn test_replaying() {
        let map = Rc::new(RefCell::new(vec![0_usize]));
        let return_value = Rc::new(RefCell::new(vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        let mut map_borrow = map.borrow_mut();
        let observer = unsafe {
            StdMapObserver::from_mut_ptr("observer", map_borrow.as_mut_ptr(), map_borrow.len())
        };
        drop(map_borrow);

        let mut feedback = ();
        let mut objective = ();

        let mut state = StdState::new(
            StdRand::new(),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut fuzzer = StdFuzzer::builder()
            .input_filter(NopInputFilter)
            .replaying_config(ReplayingConfig::new(2, 1.0, 10, true, observer.handle()))
            .scheduler(StdScheduler::new())
            .feedback(feedback)
            .objective(objective)
            .build();

        let mut event_mgr = NopEventManager::new();
        let execution_count = Rc::new(RefCell::new(0));
        let mut harness = |_i: &ValueInput<usize>| {
            let map_value = return_value.borrow_mut().remove(0);
            map.borrow_mut()[0] = map_value;
            *execution_count.borrow_mut() += 1;

            ExitKind::Ok
        };
        let mut executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(observer),
            &mut fuzzer,
            &mut state,
            &mut event_mgr,
        )
        .unwrap();

        let input: ValueInput<usize> = 42_usize.into();
        fuzzer
            .execute_input(&mut state, &mut executor, &mut event_mgr, &input)
            .unwrap();

        assert_eq!(*execution_count.borrow(), 4);
        assert!(state.corpus().is_empty());
        assert!(state.solutions().is_empty());
    }
}
