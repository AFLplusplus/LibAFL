use crate::mutators::Mutator;

pub trait ScheduledMutator: Mutator {
    fn iterations(&self) -> u64 {
        //1 << (1 + self.rand_mut().below(7))
        return 0;
    }
}
