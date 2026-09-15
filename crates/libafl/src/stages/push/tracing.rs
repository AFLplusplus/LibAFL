//! Tracing and `CmpLog` push stages for pure fuzzing engines.

use alloc::borrow::Cow;
use core::fmt::Debug;

use libafl_bolts::{Error, Named};

use super::{PushStage, StageStep};
use crate::{
    common::HasNamedMetadata,
    fuzzer::{ExecutionMode, ExecutionRequest},
    inputs::Input,
    state::{HasCorpus, HasCurrentTestcase, HasExecutionMode},
};

/// A stage that requests a tracing run for the current corpus item.
#[derive(Debug, Clone)]
pub struct TracingStage {
    name: Cow<'static, str>,
    mode: ExecutionMode,
}

/// Backwards compatibility alias for [`TracingStage`].
pub type TracingPushStage = TracingStage;

impl TracingStage {
    /// Create a new tracing stage with standard execution mode.
    #[must_use]
    pub fn new() -> Self {
        Self::with_name("TracingStage")
    }

    /// Create a new tracing stage requesting the given [`ExecutionMode`].
    #[must_use]
    pub fn with_mode(mode: ExecutionMode) -> Self {
        Self {
            name: Cow::Borrowed("TracingStage"),
            mode,
        }
    }

    /// Create a new tracing stage with a custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(name: N) -> Self {
        Self {
            name: name.into(),
            mode: ExecutionMode::Normal,
        }
    }
}

impl Default for TracingStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for TracingStage {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, OT, S> PushStage<EM, I, OT, S> for TracingStage
where
    I: Input + Clone,
    S: HasCorpus<I> + HasCurrentTestcase<I> + HasExecutionMode + HasNamedMetadata,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        if state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .is_none()
        {
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: 1,
                    testcases_done: 0,
                },
            );
        }
        state.set_execution_mode(self.mode);
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        let done = state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .is_some_and(|m| m.testcases_done >= m.testcases_to_do);

        if done {
            state.set_execution_mode(ExecutionMode::Normal);
            return Ok(StageStep::Done);
        }

        let input = state.current_input_cloned()?;
        if let Ok(meta) = state.named_metadata_mut::<super::StageProgressMetadata>(&self.name) {
            meta.testcases_done = 1;
        } else {
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: 1,
                    testcases_done: 1,
                },
            );
        }

        Ok(StageStep::Execute(
            ExecutionRequest::single(input).with_mode(self.mode),
        ))
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        state.set_execution_mode(ExecutionMode::Normal);
        let _ = state
            .named_metadata_map_mut()
            .remove::<super::StageProgressMetadata>(&self.name);
        Ok(())
    }
}

/// A specialized tracing stage for `AFL++ CmpLog` instrumentation.
#[derive(Debug, Clone)]
pub struct AflppCmplogTracingStage {
    name: Cow<'static, str>,
}

/// Backwards compatibility alias for [`AflppCmplogTracingStage`].
pub type AflppCmplogTracingPushStage = AflppCmplogTracingStage;

impl AflppCmplogTracingStage {
    /// Create a new `CmpLog` tracing stage.
    #[must_use]
    pub fn new() -> Self {
        Self::with_name("AflppCmplogTracingStage")
    }

    /// Create a new `CmpLog` tracing stage with custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(name: N) -> Self {
        Self { name: name.into() }
    }
}

impl Default for AflppCmplogTracingStage {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for AflppCmplogTracingStage {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<EM, I, OT, S> PushStage<EM, I, OT, S> for AflppCmplogTracingStage
where
    I: Input + Clone,
    S: HasCorpus<I> + HasCurrentTestcase<I> + HasExecutionMode + HasNamedMetadata,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        if state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .is_none()
        {
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: 1,
                    testcases_done: 0,
                },
            );
        }
        state.set_execution_mode(ExecutionMode::CmpLog);
        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        let done = state
            .named_metadata_map()
            .get::<super::StageProgressMetadata>(&self.name)
            .is_some_and(|m| m.testcases_done >= m.testcases_to_do);

        if done {
            state.set_execution_mode(ExecutionMode::Normal);
            return Ok(StageStep::Done);
        }

        let input = state.current_input_cloned()?;
        if let Ok(meta) = state.named_metadata_mut::<super::StageProgressMetadata>(&self.name) {
            meta.testcases_done = 1;
        } else {
            state.add_named_metadata(
                &self.name,
                super::StageProgressMetadata {
                    testcases_to_do: 1,
                    testcases_done: 1,
                },
            );
        }

        Ok(StageStep::Execute(
            ExecutionRequest::single(input).with_mode(ExecutionMode::CmpLog),
        ))
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        state.set_execution_mode(ExecutionMode::Normal);
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
    use alloc::vec;

    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        events::NopEventManager,
        feedbacks::ConstFeedback,
        inputs::BytesInput,
        observers::StdMapObserver,
        state::StdState,
    };

    /// The slot a downstream crate would own for its own tracing instrumentation.
    const TRACE_CUSTOM: ExecutionMode = ExecutionMode::custom(0);

    #[test]
    fn test_tracing_push_stage() {
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

        let mut stage = TracingPushStage::with_mode(TRACE_CUSTOM);
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();
        assert_eq!(state.execution_mode(), TRACE_CUSTOM);

        let step1 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        match step1 {
            StageStep::Execute(req) => {
                assert_eq!(req.inputs.len(), 1);
            }
            _ => panic!("Expected Execute step"),
        }

        let step2 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step2, StageStep::Done));
        assert_eq!(state.execution_mode(), ExecutionMode::Normal);

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }

    #[test]
    fn test_cmplog_tracing_push_stage() {
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

        let mut stage = AflppCmplogTracingPushStage::new();
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();
        assert_eq!(state.execution_mode(), ExecutionMode::CmpLog);

        let step1 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        match step1 {
            StageStep::Execute(req) => {
                assert_eq!(req.inputs.len(), 1);
            }
            _ => panic!("Expected Execute step with Cmplog mode"),
        }

        let step2 = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(step2, StageStep::Done));
        assert_eq!(state.execution_mode(), ExecutionMode::Normal);

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
