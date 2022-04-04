//! Probabilistic sampling scheduler is a corpus scheduler that feeds the fuzzer
//! with sampled item from the corpus.

use crate::{
    bolts::rands::Rand,
    corpus::Corpus,
    inputs::Input,
    schedulers::{Scheduler, TestcaseScore},
    state::{HasCorpus, HasMetadata, HasRand},
    Error,
};
use alloc::string::String;
use core::marker::PhantomData;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

/// Conduct reservoir sampling (probabilistic sampling) over all corpus elements.
#[derive(Debug, Clone)]
pub struct ProbabilitySamplingScheduler<F, I, S>
where
    F: TestcaseScore<I, S>,
    I: Input,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    phantom: PhantomData<(F, I, S)>,
}

/// A state metadata holding a map of probability of corpus elements.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProbabilityMetadata {
    /// corpus index -> probability
    pub map: HashMap<usize, f64>,
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

impl<F, I, S> ProbabilitySamplingScheduler<F, I, S>
where
    F: TestcaseScore<I, S>,
    I: Input,
    S: HasCorpus<I> + HasMetadata + HasRand,
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
    pub fn store_probability(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        let factor = F::compute(&mut *state.corpus().get(idx)?.borrow_mut(), state)?;
        if factor == 0.0 {
            return Err(Error::IllegalState(
                "Infinity probability calculated for probabilistic sampling scheduler".into(),
            ));
        }
        let meta = state
            .metadata_mut()
            .get_mut::<ProbabilityMetadata>()
            .unwrap();
        let prob = 1.0 / factor;
        meta.map.insert(idx, prob);
        meta.total_probability += prob;
        Ok(())
    }
}

impl<F, I, S> Scheduler<I, S> for ProbabilitySamplingScheduler<F, I, S>
where
    F: TestcaseScore<I, S>,
    I: Input,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        if state.metadata().get::<ProbabilityMetadata>().is_none() {
            state.add_metadata(ProbabilityMetadata::new());
        }
        self.store_probability(state, idx)
    }

    /// Gets the next entry
    #[allow(clippy::cast_precision_loss)]
    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::Empty(String::from("No entries in corpus")))
        } else {
            let rand_prob: f64 = (state.rand_mut().below(100) as f64) / 100.0;
            let meta = state.metadata().get::<ProbabilityMetadata>().unwrap();
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
            *state.corpus_mut().current_mut() = Some(ret);
            Ok(ret)
        }
    }
}

impl<F, I, S> Default for ProbabilitySamplingScheduler<F, I, S>
where
    F: TestcaseScore<I, S>,
    I: Input,
    S: HasCorpus<I> + HasMetadata + HasRand,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use core::borrow::BorrowMut;

    use crate::{
        bolts::rands::StdRand,
        corpus::{Corpus, InMemoryCorpus, Testcase},
        inputs::{bytes::BytesInput, Input},
        schedulers::{ProbabilitySamplingScheduler, Scheduler, TestcaseScore},
        state::{HasCorpus, HasMetadata, StdState},
        Error,
    };
    use core::marker::PhantomData;

    const FACTOR: f64 = 1337.0;

    #[derive(Debug, Clone)]
    pub struct UniformDistribution<I>
    where
        I: Input,
    {
        phantom: PhantomData<I>,
    }

    impl<I, S> TestcaseScore<I, S> for UniformDistribution<I>
    where
        I: Input,
        S: HasMetadata + HasCorpus<I>,
    {
        fn compute(_: &mut Testcase<I>, _state: &S) -> Result<f64, Error> {
            Ok(FACTOR)
        }
    }

    pub type UniformProbabilitySamplingScheduler<I, S> =
        ProbabilitySamplingScheduler<UniformDistribution<I>, I, S>;

    #[test]
    fn test_prob_sampling() {
        // the first 3 probabilities will be .69, .86, .44
        let rand = StdRand::with_seed(12);

        let scheduler = UniformProbabilitySamplingScheduler::new();

        let mut corpus = InMemoryCorpus::new();
        let t1 = Testcase::with_filename(BytesInput::new(vec![0_u8; 4]), "1".into());
        let t2 = Testcase::with_filename(BytesInput::new(vec![1_u8; 4]), "2".into());

        let idx1 = corpus.add(t1).unwrap();
        let idx2 = corpus.add(t2).unwrap();

        let mut state = StdState::new(rand, corpus, InMemoryCorpus::new(), ());
        scheduler.on_add(state.borrow_mut(), idx1).unwrap();
        scheduler.on_add(state.borrow_mut(), idx2).unwrap();
        let next_idx1 = scheduler.next(&mut state).unwrap();
        let next_idx2 = scheduler.next(&mut state).unwrap();
        let next_idx3 = scheduler.next(&mut state).unwrap();
        assert_eq!(next_idx1, next_idx2);
        assert_ne!(next_idx1, next_idx3);
    }
}
