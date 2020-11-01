use crate::mutators::Mutator;
use crate::utils::{Rand, HasRand};
use crate::corpus::Corpus;
use crate::inputs::{Input, HasBytesVec};
use crate::AflError;

use std::marker::PhantomData;

/// The generic function type that identifies mutations
type MutationFunction<MutatorT, InputT> = fn(&mut MutatorT, &mut InputT) -> Result<(), AflError>;

pub trait ComposedByMutations<InputT : Input> {
    /// Get a mutation by index
    fn mutation_by_idx(&self, index: usize) -> Result<MutationFunction<Self, InputT>, AflError>;

    /// Get the number of mutations
    fn mutations_count(&self) -> usize;

    /// Add a mutation
    fn add_mutation(&mut self, mutation: MutationFunction<Self, InputT>);
}

pub trait ScheduledMutator<InputT : Input, RandT: Rand>: Mutator<InputT, RandT> + ComposedByMutations<InputT> {
    /// Computer the number of iterations used to apply stacked mutations
    fn iterations(&mut self, _input: &InputT) -> u64 {
        1 << (1 + self.rand_mut().below(7))
    }

    /// Get the next mutation to apply
    fn schedule(&mut self, _input: &InputT) -> Result<MutationFunction<Self, InputT>, AflError> {
        let count = self.mutations_count() as u64;
        if count == 0 {
            return Err(AflError::Empty("no mutations".to_string()));
        }
        let idx;
        {
            idx = self.rand_mut().below(count) as usize;
        }
        self.mutation_by_idx(idx)
    }

    /// New default implementation for mutate
    /// Implementations must forward mutate() to this method
    fn scheduled_mutate(&mut self, input: &mut InputT, _stage_idx: i32) -> Result<(), AflError> {
        let num = self.iterations(input);
        for _ in 0..num {
            self.schedule(input)?(self, input)?;
        }
        Ok(())
    }
}

pub struct DefaultScheduledMutator<InputT : Input, RandT: Rand> {
    rand: Box<RandT>,
    corpus: Option<Box<dyn Corpus<InputT, RandT>>>,
    mutations: Vec<MutationFunction<Self, InputT>>
}

impl<InputT : Input, RandT: Rand> HasRand<RandT> for DefaultScheduledMutator<InputT, RandT> {
    fn rand(&self) -> &Box<dyn Rand> {
        &self.rand
    }
    fn rand_mut(&mut self) -> &mut Box<dyn Rand> {
        &mut self.rand
    }
}

impl<InputT : Input, RandT: Rand> ComposedByMutations<InputT> for DefaultScheduledMutator<InputT, RandT> {
    fn mutation_by_idx(&self, index: usize) -> Result<MutationFunction<Self, InputT>, AflError> {
        if index >= self.mutations.len() {
            return Err(AflError::Unknown("oob".to_string()));
        }
        Ok(self.mutations[index])
    }

    fn mutations_count(&self) -> usize {
        self.mutations.len()
    }

    fn add_mutation(&mut self, mutation: MutationFunction<Self, InputT>) {
        self.mutations.push(mutation)
    }
}

impl<InputT : Input, RandT: Rand> ScheduledMutator<InputT> for DefaultScheduledMutator<InputT, RandT> {
    // Just use the default methods
}

impl<InputT : Input, RandT: Rand> Mutator<InputT, RandT> for DefaultScheduledMutator<InputT, RandT> {
    fn mutate(&mut self, input: &mut InputT, _stage_idx: i32) -> Result<(), AflError> {
        self.scheduled_mutate(input, _stage_idx)
    }

    fn corpus(&mut self) -> &mut Option<Box<dyn Corpus>> {
        &mut self.corpus
    }
}

impl<InputT : Input, RandT: Rand> DefaultScheduledMutator<InputT> {
    /// Create a new DefaultScheduledMutator instance without mutations and corpus
    pub fn new(rand: Box<RandT>) -> Self {
        DefaultScheduledMutator {
            rand: rand,
            corpus: None,
            mutations: vec![]
        }
    }

    /// Create a new DefaultScheduledMutator instance specifying mutations and corpus too
    pub fn new_all(rand: Box<RandT>, corpus: Option<Box<dyn Corpus>>, mutations: Vec<MutationFunction<Self, InputT>>) -> Self {
        DefaultScheduledMutator {
            rand: rand,
            corpus: corpus,
            mutations: mutations
        }
    }
}

/// Bitflip mutation for inputs with a bytes vector
pub fn mutation_bitflip<MutatorT: Mutator<InputT, RandT>, InputT: Input + HasBytesVec, RandT: Rand>(mutator: &mut MutatorT, input: &mut InputT) -> Result<(), AflError> {
    let bit = mutator.rand_mut().below(input.bytes().len() as u64) as usize;
    input.bytes_mut()[bit >> 3] ^= (128 >> (bit & 7)) as u8;
    Ok(())
}

/// Schedule some selected byte level mutations given a ScheduledMutator type
pub struct HavocBytesMutator<InputT: Input + HasBytesVec, RandT: Rand, ScheduledMutatorT: ScheduledMutator<InputT, RandT>> {
    scheduled: ScheduledMutatorT,
    _phantom: PhantomData<InputT>
}

impl<InputT: Input + HasBytesVec, RandT: Rand, ScheduledMutatorT: ScheduledMutator<InputT, RandT>> Mutator<InputT, RandT> for HavocBytesMutator<InputT, RandT, ScheduledMutatorT> {
    fn mutate(&mut self, input: &mut InputT, stage_idx: i32) -> Result<(), AflError> {
        self.scheduled.mutate(input, stage_idx)
    }

    fn corpus(&mut self) -> &mut Option<Box<dyn Corpus>> {
        self.scheduled.corpus()
    }
}

impl<InputT: Input + HasBytesVec, RandT: Rand, ScheduledMutatorT: ScheduledMutator<InputT, RandT>> HasRand<RandT> for HavocBytesMutator<InputT, RandT, ScheduledMutatorT> {
    fn rand(&self) -> &Box<dyn Rand> {
        self.scheduled.rand()
    }
    fn rand_mut(&mut self) -> &mut Box<dyn Rand> {
        self.scheduled.rand_mut()
    }
}

impl<InputT: Input + HasBytesVec, RandT: Rand, ScheduledMutatorT: ScheduledMutator<InputT, RandT>> HavocBytesMutator<InputT, RandT, ScheduledMutatorT> {
    /// Create a new HavocBytesMutator instance given a ScheduledMutator to wrap
    pub fn new(mut scheduled: ScheduledMutatorT) -> Self {
        scheduled.add_mutation(mutation_bitflip);
        HavocBytesMutator {
            scheduled: scheduled,
            _phantom: PhantomData
        }
    }
}

impl<InputT: Input + HasBytesVec, RandT: Rand> HavocBytesMutator<InputT, RandT, DefaultScheduledMutator<InputT, RandT>> {
    /// Create a new HavocBytesMutator instance wrapping DefaultScheduledMutator
    pub fn new_default(rand: Box<RandT>) -> Self {
        let mut scheduled = DefaultScheduledMutator::new(rand);
        scheduled.add_mutation(mutation_bitflip);
        HavocBytesMutator {
            scheduled: scheduled,
            _phantom: PhantomData
        }
    }
}