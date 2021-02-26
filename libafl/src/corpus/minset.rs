use crate::{
    bolts::serdeany::SerdeAny,
    corpus::{Corpus, CorpusScheduler, Testcase},
    inputs::{HasLen, Input},
    state::{HasCorpus, HasMetadata},
    Error,
};

use core::{iter::IntoIterator, marker::PhantomData};
use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

/// A testcase metadata saying if a testcase is favored
#[derive(Serialize, Deserialize)]
pub struct IsFavoredMetadata {}

crate::impl_serdeany!(IsFavoredMetadata);

/// A state metadata holding a map of favoreds testcases for each map entry
#[derive(Serialize, Deserialize)]
pub struct TopRatedsMetadata {
    /// map index -> corpus index
    pub map: HashMap<usize, usize>,
}

crate::impl_serdeany!(TopRatedsMetadata);

impl TopRatedsMetadata {
    pub fn new() -> Self {
        Self {
            map: HashMap::default(),
        }
    }
}

pub trait FavFactor<I>
where
    I: Input,
{
    fn compute(testcase: &mut Testcase<I>) -> Result<u64, Error>;
}

pub struct LenTimeMulFavFactor<I>
where
    I: Input + HasLen,
{
    phantom: PhantomData<I>,
}

impl<I> FavFactor<I> for LenTimeMulFavFactor<I>
where
    I: Input + HasLen,
{
    fn compute(entry: &mut Testcase<I>) -> Result<u64, Error> {
        Ok(entry.exec_time().map_or(1, |d| d.as_millis()) as u64 * entry.cached_len()? as u64)
    }
}

pub struct MinimizerCorpusScheduler<C, CS, F, I, IT, S>
where
    CS: CorpusScheduler<I, S>,
    F: FavFactor<I>,
    I: Input,
    IT: IntoIterator<Item = usize> + SerdeAny,
    for<'a> &'a IT: IntoIterator<Item = usize>,
    S: HasCorpus<C, I> + HasMetadata,
    C: Corpus<I>,
{
    base: CS,
    phantom: PhantomData<(C, F, I, IT, S)>,
}

impl<C, CS, F, I, IT, S> CorpusScheduler<I, S> for MinimizerCorpusScheduler<C, CS, F, I, IT, S>
where
    CS: CorpusScheduler<I, S>,
    F: FavFactor<I>,
    I: Input,
    IT: IntoIterator<Item = usize> + SerdeAny,
    for<'a> &'a IT: IntoIterator<Item = usize>,
    S: HasCorpus<C, I> + HasMetadata,
    C: Corpus<I>,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        self.base.on_add(state, idx)
    }

    /// Replaces the testcase at the given idx
    fn on_replace(&self, state: &mut S, idx: usize, testcase: &Testcase<I>) -> Result<(), Error> {
        self.base.on_replace(state, idx, testcase)
    }

    /// Removes an entry from the corpus, returning it if it was present.
    fn on_remove(
        &self,
        state: &mut S,
        idx: usize,
        testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        self.base.on_remove(state, idx, testcase)
    }

    // TODO: IntoIter
    /// Gets the next entry
    fn next(&self, state: &mut S) -> Result<usize, Error> {
        self.base.next(state)
    }
}

impl<C, CS, F, I, IT, S> MinimizerCorpusScheduler<C, CS, F, I, IT, S>
where
    CS: CorpusScheduler<I, S>,
    F: FavFactor<I>,
    I: Input,
    IT: IntoIterator<Item = usize> + SerdeAny,
    for<'a> &'a IT: IntoIterator<Item = usize>,
    S: HasCorpus<C, I> + HasMetadata,
    C: Corpus<I>,
{
    pub fn update_score(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        let mut new_favoreds = vec![];
        {
            let mut entry = state.corpus().get(idx)?.borrow_mut();
            let factor = F::compute(&mut *entry)?;
            for elem in entry.metadatas().get::<IT>().unwrap() {
                // TODO proper check for TopRatedsMetadata and create a new one if not present
                if let Some(old_idx) = state
                    .metadata()
                    .get::<TopRatedsMetadata>()
                    .unwrap()
                    .map
                    .get(&elem)
                {
                    if factor > F::compute(&mut *state.corpus().get(*old_idx)?.borrow_mut())? {
                        continue;
                    }
                }

                new_favoreds.push((elem, idx));
            }
        }

        for pair in new_favoreds {
            state
                .metadata_mut()
                .get_mut::<TopRatedsMetadata>()
                .unwrap()
                .map
                .insert(pair.0, pair.1);
        }
        Ok(())
    }

    pub fn cull(&self, state: &mut S) -> Result<(), Error> {
        let mut acc = HashSet::new();
        let top_rated = state.metadata().get::<TopRatedsMetadata>().unwrap();

        for key in top_rated.map.keys() {
            if !acc.contains(key) {
                let idx = top_rated.map.get(key).unwrap();
                let mut entry = state.corpus().get(*idx)?.borrow_mut();
                for elem in entry.metadatas().get::<IT>().unwrap() {
                    acc.insert(elem);
                }

                entry.add_metadata(IsFavoredMetadata {});
            }
        }

        Ok(())
    }

    pub fn new(base: CS) -> Self {
        Self {
            base: base,
            phantom: PhantomData,
        }
    }
}
