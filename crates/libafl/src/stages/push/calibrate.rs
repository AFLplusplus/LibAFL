//! Calibration push stage for evaluating target stability and execution time.

use alloc::borrow::Cow;
use core::fmt::Debug;

use libafl_bolts::{Error, Named};

use super::{PushStage, StageStep};
use crate::{
    common::{HasMetadata, HasNamedMetadata},
    corpus::Corpus,
    fuzzer::ExecutionRequest,
    inputs::Input,
    state::{HasCorpus, HasCurrentTestcase},
};

/// Default number of calibration runs.
pub const DEFAULT_CALIBRATION_RUNS: usize = 8;

/// Metadata tracking progress of a [`CalibrationStage`] in state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct CalibrationStageMetadata {
    /// Start timestamp of the calibration batch execution.
    pub start_time: Option<core::time::Duration>,
    /// Accumulated execution duration across calibration runs.
    pub total_exec_time: core::time::Duration,
    /// Number of calibration runs observed in `post_exec`.
    pub runs_observed: usize,
    /// Whether the calibration batch has been dispatched.
    pub done: bool,
}

libafl_bolts::impl_serdeany!(CalibrationStageMetadata);

/// A stage that performs calibration on corpus entries.
#[derive(Debug, Clone)]
pub struct CalibrationStage {
    name: Cow<'static, str>,
    runs: usize,
}

/// Backwards compatibility alias for [`CalibrationStage`].
pub type CalibrationPushStage = CalibrationStage;

impl CalibrationStage {
    /// Create a new calibration stage.
    #[must_use]
    pub fn new() -> Self {
        Self::with_runs(DEFAULT_CALIBRATION_RUNS)
    }

    /// Create a new calibration stage with a specific number of runs.
    #[must_use]
    pub fn with_runs(runs: usize) -> Self {
        Self {
            name: Cow::Borrowed("CalibrationStage"),
            runs,
        }
    }
}

impl Default for CalibrationStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for CalibrationStage {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, OT, S> PushStage<EM, I, OT, S> for CalibrationStage
where
    I: Input + Clone,
    S: HasCorpus<I> + HasCurrentTestcase<I> + HasNamedMetadata + HasMetadata,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        if state
            .named_metadata_map()
            .get::<CalibrationStageMetadata>(&self.name)
            .is_some()
        {
            return Ok(());
        }

        if state
            .current_testcase()
            .is_ok_and(|tc| tc.scheduled_count() > 0)
        {
            state.add_named_metadata(
                &self.name,
                CalibrationStageMetadata {
                    start_time: None,
                    total_exec_time: core::time::Duration::ZERO,
                    runs_observed: 0,
                    done: true,
                },
            );
            return Ok(());
        }

        let done = if let Some(meta) = state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
        {
            meta.testcases_done >= meta.testcases_to_do
        } else {
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: self.runs,
                    testcases_done: 0,
                },
            );
            false
        };
        state.add_named_metadata(
            &self.name,
            CalibrationStageMetadata {
                start_time: None,
                total_exec_time: core::time::Duration::ZERO,
                runs_observed: 0,
                done,
            },
        );
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        let done = state
            .named_metadata_map()
            .get::<CalibrationStageMetadata>(&self.name)
            .is_some_and(|m| m.done);

        if done {
            return Ok(StageStep::Done);
        }

        let input = state.current_input_cloned()?;
        let now = libafl_bolts::current_time();
        if let Ok(meta) = state.named_metadata_mut::<CalibrationStageMetadata>(&self.name) {
            meta.start_time = Some(now);
            meta.total_exec_time = core::time::Duration::ZERO;
            meta.runs_observed = 0;
            meta.done = true;
        } else {
            state.add_named_metadata(
                &self.name,
                CalibrationStageMetadata {
                    start_time: Some(now),
                    total_exec_time: core::time::Duration::ZERO,
                    runs_observed: 0,
                    done: true,
                },
            );
        }
        if let Ok(meta) = state.named_metadata_mut::<super::StageProgressMetadata>(&self.name) {
            meta.testcases_done = meta.testcases_to_do;
        }

        Ok(StageStep::Execute(ExecutionRequest::batch(
            alloc::vec![input; self.runs],
        )))
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        obs: crate::fuzzer::BorrowedObservation<'_, I, OT>,
    ) -> Result<(), Error> {
        let (total_time, runs_observed) =
            if let Ok(meta) = state.named_metadata_mut::<CalibrationStageMetadata>(&self.name) {
                meta.runs_observed += 1;
                let run_time = if let Some(d) = obs.exec_time {
                    d
                } else if let Some(start) = meta.start_time {
                    libafl_bolts::current_time().saturating_sub(start) / (self.runs as u32).max(1)
                } else {
                    core::time::Duration::ZERO
                };
                meta.total_exec_time += run_time;
                (meta.total_exec_time, meta.runs_observed)
            } else {
                let run_time = obs.exec_time.unwrap_or(core::time::Duration::ZERO);
                (run_time, 1)
            };

        let runs_u32 = (runs_observed as u32).max(1);
        let avg_time = total_time / runs_u32;

        let handicap = if let Some(psmeta) = state
            .metadata_map_mut()
            .get_mut::<crate::schedulers::powersched::SchedulerMetadata>(
        ) {
            let h = psmeta.queue_cycles();
            let run_time = obs.exec_time.unwrap_or(avg_time);
            psmeta.set_exec_time(psmeta.exec_time() + run_time);
            psmeta.set_cycles(psmeta.cycles() + 1);
            Some(h)
        } else {
            None
        };

        if let Ok(mut testcase) = state.current_testcase_mut() {
            testcase.set_exec_time(avg_time);
            if let Some(handicap) = handicap {
                let depth = match testcase.parent_id() {
                    Some(parent_id) => state
                        .corpus()
                        .get(parent_id)
                        .ok()
                        .and_then(|cell| {
                            cell.borrow()
                                .metadata_map()
                                .get::<crate::corpus::SchedulerTestcaseMetadata>()
                                .map(|m| m.depth() + 1)
                        })
                        .unwrap_or(0),
                    None => 0,
                };
                let data = if let Ok(metadata) =
                    testcase.metadata_mut::<crate::corpus::SchedulerTestcaseMetadata>()
                {
                    metadata
                } else {
                    testcase.add_metadata(crate::corpus::SchedulerTestcaseMetadata::new(depth));
                    testcase
                        .metadata_mut::<crate::corpus::SchedulerTestcaseMetadata>()
                        .unwrap()
                };
                data.set_cycle_and_time((total_time, runs_observed));
                data.set_handicap(handicap);
            }
        }
        Ok(())
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        let _ = state
            .named_metadata_map_mut()
            .remove::<CalibrationStageMetadata>(&self.name);
        let _ = state
            .named_metadata_map_mut()
            .remove::<super::StageProgressMetadata>(&self.name);
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
#[allow(
    clippy::type_complexity,
    clippy::match_wildcard_for_single_variants,
    clippy::duration_suboptimal_units
)]
mod tests {
    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        events::NopEventManager,
        feedbacks::ConstFeedback,
        fuzzer::ExecutionObservation,
        inputs::BytesInput,
        observers::StdMapObserver,
        state::StdState,
    };

    #[test]
    fn test_calibration_push_stage() {
        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![1, 2, 3, 4]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        state.set_corpus_id(id).unwrap();

        let mut stage = CalibrationPushStage::with_runs(4);
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();

        let step1 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        match step1 {
            StageStep::Execute(req) => {
                assert_eq!(req.inputs.len(), 4);
            }
            _ => panic!("Expected Execute step"),
        }

        state.add_metadata(crate::schedulers::powersched::SchedulerMetadata::new(None));
        let dummy_obs = ExecutionObservation::new(crate::executors::ExitKind::Ok, ())
            .with_exec_time(core::time::Duration::from_millis(5));
        let input = state.current_input_cloned().unwrap();
        PushStage::<NopEventManager, BytesInput, (), _>::post_exec(
            &mut stage,
            &mut state,
            &mut mgr,
            dummy_obs.as_borrowed(&input),
        )
        .unwrap();

        let step2 =
            PushStage::<NopEventManager, BytesInput, (), _>::step(&mut stage, &mut state, &mut mgr)
                .unwrap();
        assert!(matches!(step2, StageStep::Done));

        let tc = state.current_testcase().unwrap();
        assert!(tc.exec_time().is_some());
        assert!(
            tc.metadata_map()
                .get::<crate::corpus::SchedulerTestcaseMetadata>()
                .is_some()
        );
        drop(tc);

        PushStage::<NopEventManager, BytesInput, (), _>::deinit(&mut stage, &mut state, &mut mgr)
            .unwrap();
    }
}
