use alloc::{borrow::ToOwned, vec::Vec};
use core::{cell::RefCell, iter::Iterator, marker::PhantomData};
use serde::{Deserialize, Serialize};

use crate::{
    corpus::Corpus, corpus::HasTestcaseVec, corpus::Testcase, inputs::{HasLen, Input}, utils::Rand, Error,
};

pub trait FavFactor: Serialize + serde::de::DeserializeOwned + 'static
{
    fn compute<I>(testcase: &Testcase<I>) -> Result<u64, Error>
    where
        I: Input;
}

pub struct LenTimeMulFavFactor {}

// TODO time as Duration and put len into Testcase
impl FavFactor for LenTimeMulFavFactor {
    fn compute<I>(entry: &Testcase<I>) -> Result<u64, Error>
    where
        I: Input + HasLen
    {
        entry.exec_time() * entry.load_input().len()
    }
}

pub trait CorpusMinimizer {
    fn update_score<C, I, R>(corpus: &mut C, idx: usize) -> Result<(), Error>
    where
        C: Corpus<I, R>,
        I: Input,
        R: Rand;

    fn cull<C, I, R>(corpus: &mut C) -> Result<(), Error>
    where
        C: Corpus<I, R>,
        I: Input,
        R: Rand;
}

pub struct FavCorpusMinimizer<F>
where
    F: FavFactor
{
    phantom: PhantomData<F>
}

impl<F> CorpusMinimizer for FavCorpusMinimizer<F>
where
    F: FavFactor
{
    fn update_score<C, I, R>(corpus: &mut C, idx: usize) -> Result<(), Error>
    where
        C: Corpus<I, R>,
        I: Input,
        R: Rand
    {
    
    }

    fn cull<C, I, R>(corpus: &mut C) -> Result<(), Error>
    where
        C: Corpus<I, R>,
        I: Input,
        R: Rand
    {
    
    }
}


#[derive(Serialize, Deserialize)]
pub struct NoveltiesMeta {
    novelties: Vec<usize>,
}
// impl Iterator<Item = usize>

/// A Queue-like corpus, wrapping an existing Corpus instance
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct MinSetCorpus<C, F, I, IT, R, T>
where
    C: Corpus<I, R>,
    F: FavFactor,
    I: Input,
    IT: Iterator<Item = T>,
    R: Rand,
{
    corpus: C,
    pos: usize,
    // TODO rebase minset on remove()
    minset: HashSet<usize>,
    top_rated: HashMap<T, usize>,
    phantom: PhantomData<(F, I, IT, R)>,
}

impl<C, I, R> HasTestcaseVec<I> for MinSetCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    #[inline]
    fn entries(&self) -> &[RefCell<Testcase<I>>] {
        self.corpus.entries()
    }
    #[inline]
    fn entries_mut(&mut self) -> &mut Vec<RefCell<Testcase<I>>> {
        self.corpus.entries_mut()
    }
}

impl<C, I, R> Corpus<I, R> for MinSetCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    /// Returns the number of elements
    #[inline]
    fn count(&self) -> usize {
        self.corpus.count()
    }

    // TODO change add to return Result
    #[inline]
    fn add(&mut self, entry: Testcase<I>) -> usize {
        let idx = self.corpus.add(entry);
        self.update_score(idx).unwrap();
        idx
    }

    /// Removes an entry from the corpus, returning it if it was present.
    #[inline]
    fn remove(&mut self, entry: &Testcase<I>) -> Option<Testcase<I>> {
        self.corpus.remove(entry)
    }

    /// Gets a random entry
    #[inline]
    fn random_entry(&self, rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), Error> {
        self.corpus.random_entry(rand)
    }

    /// Returns the testacase we currently use
    #[inline]
    fn current_testcase(&self) -> (&RefCell<Testcase<I>>, usize) {
        (self.get(self.pos - 1), self.pos - 1)
    }

    /// Gets the next entry
    #[inline]
    fn next(&mut self, _rand: &mut R) -> Result<(&RefCell<Testcase<I>>, usize), Error> {
        self.cull();
        self.pos += 1;
        if self.corpus.count() == 0 {
            return Err(Error::Empty("Corpus".to_owned()));
        }
        if self.pos > self.corpus.count() {
            // TODO: Always loop or return informational error?
            self.pos = 1;
            self.cycles += 1;
        }
        Ok((&self.corpus.entries()[self.pos - 1], self.pos - 1))
    }
}

impl<C, I, R> MinSetCorpus<C, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    pub fn new(corpus: C) -> Self {
        Self {
            corpus: corpus,
            phantom: PhantomData,
        }
    }

    #[inline]
    pub fn corpus(&self) -> &C {
        &self.corpus
    }
    
    #[inline]
    pub fn corpus_mut(&mut self) -> &mut C {
        &mut self.corpus
    }
    
    // TODO move this functions and top rated to another struct
    // create something like MinSetCorpus<.., FavMinimizer<LenTimeMulFavFactor>>
    
    pub fn update_score(&mut self, idx: usize) -> Result<(), Error> {
        let factor = F::compute(self.entries()[idx].borrow())?;
        for elem in entry.get::<IT>() {
            if let val = self.top_rated.get_mut(elem) {
                if factor > F::compute(self.entries()[val].borrow())? {
                    continue
                }
            }

            let _ = self.top_rated.insert(elem, idx);
        }
    }
    
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
}

