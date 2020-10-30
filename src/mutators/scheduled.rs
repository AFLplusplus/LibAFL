use crate::mutators::Mutator;
use crate::inputs::Input;
use crate::AflError;

type MutationFunction = fn(&mut dyn ScheduledMutator, &mut dyn Input) -> Result<(), AflError>;

pub trait ScheduledMutator: Mutator {
    fn iterations(&self, _input: &dyn Input) -> u64 {
        //1 << (1 + self.rand_mut().below(7))
        return 1;
    }

    fn schedule(&self, _input: &dyn Input) -> Result<MutationFunction, AflError> {
        if self.mutations_count() == 0 {
            return Err(AflError::Empty("no mutations".to_string()));
        }
        self.get_mutation_by_idx(1 /* self.rand_mut().below(self.mutations_count()) */)
    }

    fn get_mutation_by_idx(&self, index: usize) -> Result<MutationFunction, AflError>;

    fn mutations_count(&self) -> usize;
}

pub struct BaseScheduledMutator {
    mutations: Vec<MutationFunction>
}

impl ScheduledMutator for BaseScheduledMutator {

    fn get_mutation_by_idx(&self, index: usize) -> Result<MutationFunction, AflError> {
        if index >= self.mutations.len() {
            return Err(AflError::Unknown("oob".to_string()));
        }
        Ok(self.mutations[index])
    }

    fn mutations_count(&self) -> usize {
        self.mutations.len()
    }

}

impl Mutator for BaseScheduledMutator {

    fn mutate_at(&mut self, _stage_idx: i32, input: &mut dyn Input) -> Result<(), AflError> {
        let num = self.iterations(input);
        for _ in 0..num {
            self.schedule(input)?(self, input)?;
        }
        Ok(())
    }

}