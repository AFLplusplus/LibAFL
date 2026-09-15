//! Generalization push stage for input generalization and gap identification.

use alloc::{borrow::Cow, vec::Vec};
use core::fmt::Debug;

use libafl_bolts::{
    Error, Named,
    tuples::{Handle, MatchNameRef},
};

use super::{PushStage, StageStep};
use crate::{
    common::{HasMetadata, HasNamedMetadata},
    corpus::HasCurrentCorpusId,
    feedbacks::map::MapNoveltiesMetadata,
    fuzzer::ExecutionRequest,
    inputs::{BytesInput, GeneralizedInputMetadata, HasMutatorBytes},
    observers::{MapObserver, ObserversTuple},
    stages::{Restartable, RetryCountRestartHelper, generalization::GENERALIZATION_STAGE_NAME},
    state::{HasCorpus, HasCurrentTestcase},
};

const MAX_GENERALIZED_LEN: usize = 8192;

/// Phase of input generalization persisted in [`GeneralizationStageMetadata`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GeneralizationPhaseState {
    /// Testing byte modifications to identify gaps.
    TestingGaps {
        /// Optional byte payload (None = gap).
        payload: Vec<Option<u8>>,
        /// Original input bytes.
        original_bytes: Vec<u8>,
        /// Map novelty indices to preserve.
        novelties: Vec<usize>,
        /// Current byte index being tested.
        current_idx: usize,
    },
    /// Generalization completed.
    Done,
}

/// Metadata tracking progress of a [`GeneralizationStage`] in state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GeneralizationStageMetadata {
    /// Current phase of generalization.
    pub phase: GeneralizationPhaseState,
}

libafl_bolts::impl_serdeany!(GeneralizationStageMetadata);

/// A stage that performs AFL++ style generalization on corpus entries.
#[derive(Debug, Clone)]
pub struct GeneralizationStage<C, O> {
    name: Cow<'static, str>,
    map_observer_handle: Handle<C>,
    _phantom: core::marker::PhantomData<O>,
}

/// Backwards compatibility alias for [`GeneralizationStage`].
pub type GeneralizationPushStage<C, O> = GeneralizationStage<C, O>;

impl<C, O> GeneralizationStage<C, O> {
    /// Create a new generalization stage.
    #[must_use]
    pub fn new(map_observer_handle: impl Into<Handle<C>>) -> Self {
        Self::with_name(map_observer_handle.into(), GENERALIZATION_STAGE_NAME)
    }

    /// Create a new generalization stage with custom name.
    #[must_use]
    pub fn with_name<N: Into<Cow<'static, str>>>(
        map_observer_handle: impl Into<Handle<C>>,
        name: N,
    ) -> Self {
        Self {
            name: name.into(),
            map_observer_handle: map_observer_handle.into(),
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<C, O> Named for GeneralizationPushStage<C, O> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<C, O, S> Restartable<S> for GeneralizationPushStage<C, O>
where
    S: HasMetadata + HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl<C, EM, O, OT, S> PushStage<EM, BytesInput, OT, S> for GeneralizationPushStage<C, O>
where
    C: AsRef<O> + Named,
    O: MapObserver,
    OT: ObserversTuple<BytesInput, S> + MatchNameRef,
    S: HasCorpus<BytesInput>
        + HasMetadata
        + HasNamedMetadata
        + HasCurrentCorpusId
        + HasCurrentTestcase<BytesInput>,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        if state
            .named_metadata_map()
            .get::<GeneralizationStageMetadata>(&self.name)
            .is_some()
        {
            return Ok(());
        }

        let entry = state.current_testcase()?;
        let novelties = if let Some(meta) = entry.metadata_map().get::<MapNoveltiesMetadata>() {
            if meta.is_empty() {
                drop(entry);
                state.add_named_metadata(
                    &self.name,
                    GeneralizationStageMetadata {
                        phase: GeneralizationPhaseState::Done,
                    },
                );
                return Ok(());
            }
            meta.to_vec()
        } else {
            drop(entry);
            state.add_named_metadata(
                &self.name,
                GeneralizationStageMetadata {
                    phase: GeneralizationPhaseState::Done,
                },
            );
            return Ok(());
        };

        let input = entry.input().clone().unwrap_or_default();
        drop(entry);
        let bytes = input.mutator_bytes();
        if bytes.len() > MAX_GENERALIZED_LEN || bytes.is_empty() {
            state.add_named_metadata(
                &self.name,
                GeneralizationStageMetadata {
                    phase: GeneralizationPhaseState::Done,
                },
            );
            return Ok(());
        }

        let payload: Vec<Option<u8>> = bytes.iter().map(|&x| Some(x)).collect();
        state.add_named_metadata(
            &self.name,
            GeneralizationStageMetadata {
                phase: GeneralizationPhaseState::TestingGaps {
                    payload,
                    original_bytes: bytes.to_vec(),
                    novelties,
                    current_idx: 0,
                },
            },
        );

        Ok(())
    }

    fn step(&mut self, state: &mut S, _manager: &mut EM) -> Result<StageStep<BytesInput>, Error> {
        let Some(meta) = state
            .named_metadata_map()
            .get::<GeneralizationStageMetadata>(&self.name)
            .cloned()
        else {
            return Ok(StageStep::Done);
        };

        match meta.phase {
            GeneralizationPhaseState::Done => Ok(StageStep::Done),
            GeneralizationPhaseState::TestingGaps {
                payload,
                original_bytes,
                novelties,
                mut current_idx,
            } => {
                if current_idx >= payload.len() {
                    let gen_meta = GeneralizedInputMetadata::generalized_from_options(&payload);
                    let mut tc = state.current_testcase_mut()?;
                    tc.add_metadata(gen_meta);
                    drop(tc);

                    if let Ok(m) =
                        state.named_metadata_mut::<GeneralizationStageMetadata>(&self.name)
                    {
                        m.phase = GeneralizationPhaseState::Done;
                    }
                    return Ok(StageStep::Done);
                }

                // Test next byte modification
                let mut trial_bytes = original_bytes.clone();
                trial_bytes[current_idx] = trial_bytes[current_idx].wrapping_add(255);
                current_idx += 1;

                if let Ok(m) = state.named_metadata_mut::<GeneralizationStageMetadata>(&self.name) {
                    m.phase = GeneralizationPhaseState::TestingGaps {
                        payload,
                        original_bytes,
                        novelties,
                        current_idx,
                    };
                }

                Ok(StageStep::Execute(ExecutionRequest::single(
                    BytesInput::new(trial_bytes),
                )))
            }
        }
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        obs: crate::fuzzer::BorrowedObservation<'_, BytesInput, OT>,
    ) -> Result<(), Error> {
        let Some(meta) = state
            .named_metadata_map()
            .get::<GeneralizationStageMetadata>(&self.name)
            .cloned()
        else {
            return Ok(());
        };

        if let GeneralizationPhaseState::TestingGaps {
            mut payload,
            original_bytes,
            novelties,
            current_idx,
        } = meta.phase
        {
            if let Some(observer) = obs.observers.get(&self.map_observer_handle) {
                let observer = observer.as_ref();
                let initial = observer.initial();
                let mut matches = true;
                for &idx in &novelties {
                    if idx >= observer.len() || observer.get(idx) == initial {
                        matches = false;
                        break;
                    }
                }
                if matches && current_idx > 0 && current_idx <= payload.len() {
                    payload[current_idx - 1] = None;
                }
            }

            if current_idx >= payload.len() {
                let gen_meta = GeneralizedInputMetadata::generalized_from_options(&payload);
                let mut tc = state.current_testcase_mut()?;
                tc.add_metadata(gen_meta);
                drop(tc);

                if let Ok(m) = state.named_metadata_mut::<GeneralizationStageMetadata>(&self.name) {
                    m.phase = GeneralizationPhaseState::Done;
                }
            } else if let Ok(m) =
                state.named_metadata_mut::<GeneralizationStageMetadata>(&self.name)
            {
                m.phase = GeneralizationPhaseState::TestingGaps {
                    payload,
                    original_bytes,
                    novelties,
                    current_idx,
                };
            }
        }
        Ok(())
    }

    fn deinit(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        let _ = state
            .named_metadata_map_mut()
            .remove::<GeneralizationStageMetadata>(&self.name);
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

    use libafl_bolts::{rands::StdRand, tuples::Handled};

    use super::*;
    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        events::NopEventManager,
        executors::ExitKind,
        feedbacks::{ConstFeedback, map::MapNoveltiesMetadata},
        fuzzer::ExecutionObservation,
        inputs::BytesInput,
        observers::StdMapObserver,
        state::StdState,
    };

    static mut MAP: [u8; 16] = [1; 16];

    #[test]
    fn test_generalization_push_stage() {
        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let mut testcase = Testcase::new(BytesInput::new(vec![0x41, 0x42, 0x43, 0x44]));
        testcase.add_metadata(MapNoveltiesMetadata::new(vec![0, 1]));
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

        let map_ptr = &raw mut MAP as *mut u8;
        let observer = unsafe { StdMapObserver::from_mut_ptr("cov", map_ptr, 16) };
        let handle = observer.handle();

        let mut stage = GeneralizationPushStage::new(handle);
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();

        let mut steps = 0;
        while let StageStep::Execute(req) = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap()
        {
            assert_eq!(req.inputs.len(), 1);
            steps += 1;
            let obs = ExecutionObservation::new(ExitKind::Ok, (observer.clone(), ()));
            stage
                .post_exec(&mut state, &mut mgr, obs.as_borrowed(&req.inputs[0]))
                .unwrap();
        }

        assert!(steps > 0);
        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
    }
}
