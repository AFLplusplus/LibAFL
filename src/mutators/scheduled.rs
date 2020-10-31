use crate::mutators::Mutator;
use crate::utils::Rand;
use crate::corpus::Corpus;
use crate::inputs::{Input, BytesInput};
use crate::AflError;

type MutationFunction<MutatorT, InputT> = fn(&mut MutatorT, &mut InputT) -> Result<(), AflError>;

pub trait ScheduledMutator<InputT : Input>: Mutator<InputT> {
    fn iterations(&mut self, _input: &InputT) -> u64 {
        1 << (1 + self.rand().below(7))
    }

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

    fn mutation_by_idx(&self, index: usize) -> Result<MutationFunction<Self, InputT>, AflError>;

    fn mutations_count(&self) -> usize;

    fn add_mutation(&mut self, mutation: MutationFunction<Self, InputT>);

}

pub struct DefaultScheduledMutator<InputT : Input> {
    rand: Box<dyn Rand>,
    corpus: Option<Box<dyn Corpus>>,
    mutations: Vec<MutationFunction<Self, InputT>>
}

impl<InputT : Input> ScheduledMutator<InputT> for DefaultScheduledMutator<InputT> {

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

impl<InputT : Input> Mutator<InputT> for DefaultScheduledMutator<InputT> {

    fn rand(&mut self) -> &mut Box<dyn Rand> {
        &mut self.rand
    }

    fn mutate(&mut self, input: &mut InputT, _stage_idx: i32) -> Result<(), AflError> {
        let num = self.iterations(input);
        for _ in 0..num {
            self.schedule(input)?(self, input)?;
        }
        Ok(())
    }

    fn corpus(&mut self) -> &mut Option<Box<dyn Corpus>> {
        &mut self.corpus
    }

}

impl<InputT : Input> DefaultScheduledMutator<InputT> {
    pub fn new(rand: Box<dyn Rand>) -> Self {
        DefaultScheduledMutator {
            rand: rand,
            corpus: None,
            mutations: vec![]
        }
    }

    pub fn new_all(rand: Box<dyn Rand>, corpus: Option<Box<dyn Corpus>>, mutations: Vec<MutationFunction<Self, InputT>>) -> Self {
        DefaultScheduledMutator {
            rand: rand,
            corpus: corpus,
            mutations: mutations
        }
    }
}

pub fn mutation_bitflip<MutatorT: Mutator<BytesInput>>(mutator: &mut MutatorT, input: &mut BytesInput) -> Result<(), AflError> {
    let bit = mutator.rand().below(input.bytes.len() as u64) as usize;
    input.bytes[bit >> 3] ^= (128 >> (bit & 7)) as u8;
    Ok(())
}

pub struct HavocMutator<ScheduledMutatorT: ScheduledMutator<BytesInput>> {
    scheduled: ScheduledMutatorT,
}

impl<ScheduledMutatorT: ScheduledMutator<BytesInput>> Mutator<BytesInput> for HavocMutator<ScheduledMutatorT> {

    fn rand(&mut self) -> &mut Box<dyn Rand> {
        self.scheduled.rand()
    }

    fn mutate(&mut self, input: &mut BytesInput, stage_idx: i32) -> Result<(), AflError> {
        self.scheduled.mutate(input, stage_idx)
    }

    fn corpus(&mut self) -> &mut Option<Box<dyn Corpus>> {
        self.scheduled.corpus()
    }

}

impl<ScheduledMutatorT: ScheduledMutator<BytesInput>> HavocMutator<ScheduledMutatorT> {
    pub fn new(mut scheduled: ScheduledMutatorT) -> Self {
        scheduled.add_mutation(mutation_bitflip);
        HavocMutator {
            scheduled: scheduled
        }
    }
}

impl HavocMutator<DefaultScheduledMutator<BytesInput>> {
    pub fn new_default(rand: Box<dyn Rand>) -> Self {
        let mut scheduled = DefaultScheduledMutator::new(rand);
        scheduled.add_mutation(mutation_bitflip);
        HavocMutator {
            scheduled: scheduled
        }
    }
}