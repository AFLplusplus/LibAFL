use crate::corpus::Corpus;
use crate::inputs::{HasBytesVec, Input};
use crate::mutators::{HasOptionCorpus, Mutator};
use crate::utils::{HasRand, Rand};
use crate::AflError;

use std::marker::PhantomData;
use std::rc::Rc;
use std::cell::RefCell;

/// The generic function type that identifies mutations
type MutationFunction<M, I> = fn(&mut M, &mut I) -> Result<(), AflError>;

pub trait ComposedByMutations<I>
where
    I: Input,
{
    /// Get a mutation by index
    fn mutation_by_idx(&self, index: usize) -> Result<MutationFunction<Self, I>, AflError>;

    /// Get the number of mutations
    fn mutations_count(&self) -> usize;

    /// Add a mutation
    fn add_mutation(&mut self, mutation: MutationFunction<Self, I>);
}

pub trait ScheduledMutator<I>: Mutator<I> + HasOptionCorpus<I> + ComposedByMutations<I>
where
    I: Input,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&mut self, _input: &I) -> u64 {
        1 << (1 + self.rand_below(7))
    }

    /// Get the next mutation to apply
    fn schedule(&mut self, _input: &I) -> Result<MutationFunction<Self, I>, AflError> {
        let count = self.mutations_count() as u64;
        if count == 0 {
            return Err(AflError::Empty("no mutations".to_string()));
        }
        let idx;
        {
            idx = self.rand_below(count) as usize;
        }
        self.mutation_by_idx(idx)
    }

    /// New default implementation for mutate
    /// Implementations must forward mutate() to this method
    fn scheduled_mutate(&mut self, input: &mut I, _stage_idx: i32) -> Result<(), AflError> {
        let num = self.iterations(input);
        for _ in 0..num {
            self.schedule(input)?(self, input)?;
        }
        Ok(())
    }
}

pub struct DefaultScheduledMutator<'a, I, R, C>
where
    I: Input,
    R: Rand,
    C: Corpus<I>,
{
    rand: Rc<RefCell<R>>,
    corpus: Option<Box<C>>,
    mutations: Vec<MutationFunction<Self, I>>,
}

impl<'a, I, R, C> HasRand for DefaultScheduledMutator<'_, I, R, C>
where
    I: Input,
    R: Rand,
    C: Corpus<I>,
{
    type R = R;

    fn rand(&self) -> &Rc<RefCell<Self::R>> {
        &self.rand
    }
}

impl<I, R, C> HasOptionCorpus<I> for DefaultScheduledMutator<'_, I, R, C>
where
    I: Input,
    R: Rand,
    C: Corpus<I>,
{
    type C = C;

    fn corpus(&self) -> &Option<Box<Self::C>> {
        &self.corpus
    }

    fn corpus_mut(&mut self) -> &mut Option<Box<Self::C>> {
        &mut self.corpus
    }

    fn set_corpus(&mut self, corpus: Option<Box<Self::C>>) {
        self.corpus = corpus
    }
}

impl<'a, I, R, C> Mutator<I> for DefaultScheduledMutator<'_, I, R, C>
where
    I: Input,
    R: Rand,
    C: Corpus<I>,
{
    fn mutate(&mut self, input: &mut I, _stage_idx: i32) -> Result<(), AflError> {
        self.scheduled_mutate(input, _stage_idx)
    }
}

impl<'a, I, R, C> ComposedByMutations<I> for DefaultScheduledMutator<'_, I, R, C>
where
    I: Input,
    R: Rand,
    C: Corpus<I>,
{
    fn mutation_by_idx(&self, index: usize) -> Result<MutationFunction<Self, I>, AflError> {
        if index >= self.mutations.len() {
            return Err(AflError::Unknown("oob".to_string()));
        }
        Ok(self.mutations[index])
    }

    fn mutations_count(&self) -> usize {
        self.mutations.len()
    }

    fn add_mutation(&mut self, mutation: MutationFunction<Self, I>) {
        self.mutations.push(mutation)
    }
}

impl<'a, I, R, C> ScheduledMutator<I> for DefaultScheduledMutator<'_, I, R, C>
where
    I: Input,
    R: Rand,
    C: Corpus<I>,
{
    // Just use the default methods
}

impl<'a, I, R, C> DefaultScheduledMutator<'a, I, R, C>
where
    I: Input,
    R: Rand,
    C: Corpus<I>,
{
    /// Create a new DefaultScheduledMutator instance without mutations and corpus
    pub fn new(rand: &Rc<RefCell<R>>) -> Self {
        DefaultScheduledMutator {
            rand: Rc::clone(rand),
            corpus: None,
            mutations: vec![],
        }
    }

    /// Create a new DefaultScheduledMutator instance specifying mutations and corpus too
    pub fn new_all(
        rand: &Rc<RefCell<R>>,
        corpus: Option<Box<C>>,
        mutations: Vec<MutationFunction<Self, I>>,
    ) -> Self {
        DefaultScheduledMutator {
            rand: Rc::clone(rand),
            corpus: corpus,
            mutations: mutations,
        }
    }
}

/// Bitflip mutation for inputs with a bytes vector
pub fn mutation_bitflip<M, I>(mutator: &mut M, input: &mut I) -> Result<(), AflError>
where
    M: Mutator<I>,
    I: Input + HasBytesVec,
{
    let bit = mutator.rand_below(input.bytes().len() as u64) as usize;
    input.bytes_mut()[bit >> 3] ^= (128 >> (bit & 7)) as u8;
    Ok(())
}

/// Schedule some selected byte level mutations given a ScheduledMutator type
pub struct HavocBytesMutator<I, S>
where
    I: Input + HasBytesVec,
    S: ScheduledMutator<I>,
{
    scheduled: S,
    phantom: PhantomData<I>,
}

impl<I, S> HasRand for HavocBytesMutator<I, S>
where
    I: Input + HasBytesVec,
    S: ScheduledMutator<I>,
{
    type R = S::R;

    fn rand(&self) -> &Rc<RefCell<Self::R>> {
        &self.scheduled.rand()
    }
}

impl<I, S> HasOptionCorpus<I> for HavocBytesMutator<I, S>
where
    I: Input + HasBytesVec,
    S: ScheduledMutator<I>,
{
    type C = S::C;

    fn corpus(&self) -> &Option<Box<Self::C>> {
        self.scheduled.corpus()
    }

    fn corpus_mut(&mut self) -> &mut Option<Box<Self::C>> {
        self.scheduled.corpus_mut()
    }

    fn set_corpus(&mut self, corpus: Option<Box<Self::C>>) {
        self.scheduled.set_corpus(corpus)
    }
}

impl<I, S> Mutator<I> for HavocBytesMutator<I, S>
where
    I: Input + HasBytesVec,
    S: ScheduledMutator<I>,
{
    fn mutate(&mut self, input: &mut I, stage_idx: i32) -> Result<(), AflError> {
        self.scheduled.mutate(input, stage_idx)
    }
}

impl<I, S> HavocBytesMutator<I, S>
where
    I: Input + HasBytesVec,
    S: ScheduledMutator<I>,
{
    /// Create a new HavocBytesMutator instance given a ScheduledMutator to wrap
    pub fn new(mut scheduled: S) -> Self {
        scheduled.add_mutation(mutation_bitflip);
        HavocBytesMutator {
            scheduled: scheduled,
            phantom: PhantomData,
        }
    }
}

impl<'a, I, R, C> HavocBytesMutator<I, DefaultScheduledMutator<'a, I, R, C>>
where
    I: Input + HasBytesVec,
    R: Rand,
    C: Corpus<I>,
{
    /// Create a new HavocBytesMutator instance wrapping DefaultScheduledMutator
    pub fn new_default(rand: &Rc<RefCell<R>>) -> Self {
        let mut scheduled = DefaultScheduledMutator::<'a, I, R, C>::new(rand);
        scheduled.add_mutation(mutation_bitflip);
        HavocBytesMutator {
            scheduled: scheduled,
            phantom: PhantomData,
        }
    }
}
