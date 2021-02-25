use core::marker::PhantomData;

use crate::{
    corpus::{Corpus, CorpusScheduler, Testcase},
    inputs::{HasLen, Input},
    state::HasCorpus,
    Error,
};

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

pub struct MinimizerCorpusScheduler<C, CS, F, I, S>
where
CS: CorpusScheduler<I, S>,
F: FavFactor<I>,
I: Input,
S: HasCorpus<C, I>,
C: Corpus<I>
{
    base: CS,
    phantom: PhantomData<(C, F, I, S)>,
}

impl<C, CS, F, I, S> CorpusScheduler<I, S> for MinimizerCorpusScheduler<C, CS, F, I, S>
where
CS: CorpusScheduler<I, S>,
F: FavFactor<I>,
I: Input,
S: HasCorpus<C, I>,
C: Corpus<I>
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

impl<C, CS, F, I, S> MinimizerCorpusScheduler<C, CS, F, I, S>
where
    CS: CorpusScheduler<I, S>,
    F: FavFactor<I>,
    I: Input,
    S: HasCorpus<C, I>,
    C: Corpus<I>
{
    /*pub fn update_score(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        let entry = state.corpus().get(idx)?.borrow_mut();
        let factor = F::compute(&mut *entry)?;
        for elem in entry.get::<IT>() {
            if let val = self.top_rated.get_mut(elem) {
                if factor > F::compute(self.entries()[val].borrow())? {
                    continue
                }
            }
    
            let _ = self.top_rated.insert(elem, idx);
        }
    }*/

    pub fn new(base: CS) -> Self {
        Self {
            base: base,
            phantom: PhantomData,
        }
    }
}

/*
pub fn cull(&mut self) {
    let mut acc = HashSet::new();
    self.minset.clear();

    for key in self.top_rated.keys() {
        if !acc.contains(key) {
            let idx = self.top_rated.get(key).unwrap();
            let entry = self.entries()[idx].borrow();
            for elem in entry.get::<IT>() {
                acc.insert(elem);
            }

            self.minset.insert(idx);
        }
    }
}
*/
