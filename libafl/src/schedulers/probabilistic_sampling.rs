//! Probabilistic sampling scheduler is a corpus scheduler that feeds the fuzzer
//! with sampled item from the corpus.

use alloc::string::String;
use core::marker::PhantomData;

use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

use crate::{
    bolts::rands::Rand,
    corpus::{Corpus, CorpusId},
    inputs::UsesInput,
    schedulers::{Scheduler, TestcaseScore},
    state::{HasCorpus, HasMetadata, HasRand, UsesState},
    Error,
};

/// Conduct reservoir sampling (probabilistic sampling) over all corpus elements.
#[derive(Debug, Clone)]
pub struct ProbabilitySamplingScheduler<F, S>
where
    S: UsesInput,
{
    phantom: PhantomData<(F, S)>,
}

/// A state metadata holding a map of probability of corpus elements.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProbabilityMetadata {
    /// corpus index -> probability
    pub map: HashMap<CorpusId, f64>,
    /// total probability of all items in the map
    pub total_probability: f64,
}

crate::impl_serdeany!(ProbabilityMetadata);

impl ProbabilityMetadata {
    /// Creates a new [`struct@ProbabilityMetadata`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
            total_probability: 0.0,
        }
    }
}

impl Default for ProbabilityMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl<F, S> ProbabilitySamplingScheduler<F, S>
where
    F: TestcaseScore<S>,
    S: HasCorpus + HasMetadata + HasRand,
{
    /// Creates a new [`struct@ProbabilitySamplingScheduler`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    /// Calculate the score and store in `ProbabilityMetadata`
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::unused_self)]
    pub fn store_probability(&self, state: &mut S, idx: CorpusId) -> Result<(), Error> {
        let factor = F::compute(state, &mut *state.corpus().get(idx)?.borrow_mut())?;
        if factor == 0.0 {
            return Err(Error::illegal_state(
                "Infinity probability calculated for probabilistic sampling scheduler",
            ));
        }
        let meta = state
            .metadata_map_mut()
            .get_mut::<ProbabilityMetadata>()
            .unwrap();
        let prob = 1.0 / factor;
        meta.map.insert(idx, prob);
        meta.total_probability += prob;
        Ok(())
    }
}

impl<F, S> UsesState for ProbabilitySamplingScheduler<F, S>
where
    S: UsesInput,
{
    type State = S;
}

impl<F, S> Scheduler for ProbabilitySamplingScheduler<F, S>
where
    F: TestcaseScore<S>,
    S: HasCorpus + HasMetadata + HasRand,
{
    fn on_add(&mut self, state: &mut Self::State, idx: CorpusId) -> Result<(), Error> {
        let current_idx = *state.corpus().current();
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .set_parent_id_optional(current_idx);

        if state.metadata_map().get::<ProbabilityMetadata>().is_none() {
            state.add_metadata(ProbabilityMetadata::new());
        }
        self.store_probability(state, idx)
    }

    /// Gets the next entry
    #[allow(clippy::cast_precision_loss)]
    fn next(&mut self, state: &mut Self::State) -> Result<CorpusId, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty(String::from("No entries in corpus")))
        } else {
            let rand_prob: f64 = (state.rand_mut().below(100) as f64) / 100.0;
            let meta = state.metadata_map().get::<ProbabilityMetadata>().unwrap();
            let threshold = meta.total_probability * rand_prob;
            let mut k: f64 = 0.0;
            let mut ret = *meta.map.keys().last().unwrap();
            for (idx, prob) in meta.map.iter() {
                k += prob;
                if k >= threshold {
                    ret = *idx;
                    break;
                }
            }
            self.set_current_scheduled(state, Some(ret))?;
            Ok(ret)
        }
    }

    /// Set current fuzzed corpus id and `scheduled_count`
    fn set_current_scheduled(
        &mut self,
        state: &mut Self::State,
        next_idx: Option<CorpusId>,
    ) -> Result<(), Error> {
        *state.corpus_mut().current_mut() = next_idx;
        Ok(())
    }
}

impl<F, S> Default for ProbabilitySamplingScheduler<F, S>
where
    F: TestcaseScore<S>,
    S: HasCorpus + HasMetadata + HasRand,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use core::{borrow::BorrowMut, marker::PhantomData};

    use crate::{
        bolts::rands::StdRand,
        corpus::{Corpus, InMemoryCorpus, Testcase},
        feedbacks::ConstFeedback,
        inputs::{bytes::BytesInput, Input, UsesInput},
        schedulers::{ProbabilitySamplingScheduler, Scheduler, TestcaseScore},
        state::{HasCorpus, HasMetadata, StdState},
        Error,
    };

    const FACTOR: f64 = 1337.0;

    #[derive(Debug, Clone)]
    pub struct UniformDistribution<I>
    where
        I: Input,
    {
        phantom: PhantomData<I>,
    }

    impl<S> TestcaseScore<S> for UniformDistribution<S::Input>
    where
        S: HasMetadata + HasCorpus,
    {
        fn compute(_state: &S, _: &mut Testcase<S::Input>) -> Result<f64, Error> {
            Ok(FACTOR)
        }
    }

    pub type UniformProbabilitySamplingScheduler<S> =
        ProbabilitySamplingScheduler<UniformDistribution<<S as UsesInput>::Input>, S>;

    #[test]
    fn test_prob_sampling() {
        // the first 3 probabilities will be .69, .86, .44
        let rand = StdRand::with_seed(12);

        let mut scheduler = UniformProbabilitySamplingScheduler::new();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);

        let mut corpus = InMemoryCorpus::new();
        let t1 = Testcase::with_filename(BytesInput::new(vec![0_u8; 4]), "1".into());
        let t2 = Testcase::with_filename(BytesInput::new(vec![1_u8; 4]), "2".into());

        let idx1 = corpus.add(t1).unwrap();
        let idx2 = corpus.add(t2).unwrap();

        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        scheduler.on_add(state.borrow_mut(), idx1).unwrap();
        scheduler.on_add(state.borrow_mut(), idx2).unwrap();
        let next_idx1 = scheduler.next(&mut state).unwrap();
        let next_idx2 = scheduler.next(&mut state).unwrap();
        let next_idx3 = scheduler.next(&mut state).unwrap();
        assert_eq!(next_idx1, next_idx2);
        assert_ne!(next_idx1, next_idx3);
    }
}
