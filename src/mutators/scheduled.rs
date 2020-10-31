use crate::mutators::Mutator;
use crate::utils::Rand;
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

pub trait ScheduledMutator<InputT : Input>: Mutator<InputT> + ComposedByMutations<InputT> {
    /// Computer the number of iterations used to apply stacked mutations
    fn iterations(&mut self, _input: &InputT) -> u64 {
        1 << (1 + self.rand().below(7))
    }

    /// Get the next mutation to apply
    fn schedule(&mut self, _input: &InputT) -> Result<MutationFunction<Self, InputT>, AflError> {
        let count = self.mutations_count() as u64;
        if count == 0 {
            return Err(AflError::Empty("no mutations".to_string()));
        }
        let idx;
        {
            idx = self.rand().below(count) as usize;
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

pub struct DefaultScheduledMutator<InputT : Input> {
    rand: Box<dyn Rand>,
    corpus: Option<Box<dyn Corpus>>,
    mutations: Vec<MutationFunction<Self, InputT>>
}

impl<InputT : Input> ComposedByMutations<InputT> for DefaultScheduledMutator<InputT> {
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

impl<InputT : Input> ScheduledMutator<InputT> for DefaultScheduledMutator<InputT> {
    // Just use the default methods
}

impl<InputT : Input> Mutator<InputT> for DefaultScheduledMutator<InputT> {
    fn rand(&mut self) -> &mut Box<dyn Rand> {
        &mut self.rand
    }

    fn mutate(&mut self, input: &mut InputT, _stage_idx: i32) -> Result<(), AflError> {
        self.scheduled_mutate(input, _stage_idx)
    }

    fn corpus(&mut self) -> &mut Option<Box<dyn Corpus>> {
        &mut self.corpus
    }
}

impl<InputT : Input> DefaultScheduledMutator<InputT> {
    /// Create a new DefaultScheduledMutator instance without mutations and corpus
    pub fn new(rand: Box<dyn Rand>) -> Self {
        DefaultScheduledMutator {
            rand: rand,
            corpus: None,
            mutations: vec![]
        }
    }

    /// Create a new DefaultScheduledMutator instance specifying mutations and corpus too
    pub fn new_all(rand: Box<dyn Rand>, corpus: Option<Box<dyn Corpus>>, mutations: Vec<MutationFunction<Self, InputT>>) -> Self {
        DefaultScheduledMutator {
            rand: rand,
            corpus: corpus,
            mutations: mutations
        }
    }
}

/// Bitflip mutation for inputs with a bytes vector
pub fn mutation_bitflip<MutatorT: Mutator<InputT>, InputT: Input + HasBytesVec>(mutator: &mut MutatorT, input: &mut InputT) -> Result<(), AflError> {
    let bit = mutator.rand().below(input.bytes().len() as u64) as usize;
    input.bytes_mut()[bit >> 3] ^= (128 >> (bit & 7)) as u8;
    Ok(())
}

/// Schedule some selected byte level mutations given a ScheduledMutator type
pub struct HavocBytesMutator<ScheduledMutatorT: ScheduledMutator<InputT>, InputT: Input + HasBytesVec> {
    scheduled: ScheduledMutatorT,
    _phantom: PhantomData<InputT>
}

impl<ScheduledMutatorT: ScheduledMutator<InputT>, InputT: Input + HasBytesVec> Mutator<InputT> for HavocBytesMutator<ScheduledMutatorT, InputT> {
    fn rand(&mut self) -> &mut Box<dyn Rand> {
        self.scheduled.rand()
    }

    fn mutate(&mut self, input: &mut InputT, stage_idx: i32) -> Result<(), AflError> {
        self.scheduled.mutate(input, stage_idx)
    }

    fn corpus(&mut self) -> &mut Option<Box<dyn Corpus>> {
        self.scheduled.corpus()
    }
}

impl<ScheduledMutatorT: ScheduledMutator<InputT>, InputT: Input + HasBytesVec> HavocBytesMutator<ScheduledMutatorT, InputT> {
    /// Create a new HavocBytesMutator instance given a ScheduledMutator to wrap
    pub fn new(mut scheduled: ScheduledMutatorT) -> Self {
        scheduled.add_mutation(mutation_bitflip);
        HavocBytesMutator {
            scheduled: scheduled,
            _phantom: PhantomData
        }
    }
}

impl<InputT: Input + HasBytesVec> HavocBytesMutator<DefaultScheduledMutator<InputT>, InputT> {
    /// Create a new HavocBytesMutator instance wrapping DefaultScheduledMutator
    pub fn new_default(rand: Box<dyn Rand>) -> Self {
        let mut scheduled = DefaultScheduledMutator::new(rand);
        scheduled.add_mutation(mutation_bitflip);
        HavocBytesMutator {
            scheduled: scheduled,
            _phantom: PhantomData
        }
    }
}