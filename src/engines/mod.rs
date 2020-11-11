extern crate alloc;
use crate::corpus::testcase::Testcase;
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::stages::Stage;
use crate::AflError;

use alloc::rc::Rc;
use core::cell::RefCell;

pub trait Engine<I>
where
    I: Input,
{
    fn feedbacks(&self) -> &Vec<Box<dyn Feedback<I>>>;

    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>>;

    fn add_feedback(&mut self, feedback: Box<dyn Feedback<I>>) {
        self.feedbacks_mut().push(feedback);
    }

    fn stages(&self) -> &Vec<Box<dyn Stage<I>>>;

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<I>>>;

    fn add_stage(&mut self, stage: Box<dyn Stage<I>>) {
        self.stages_mut().push(stage);
    }

    fn fuzz_one(&mut self, testcase: &Rc<RefCell<Testcase<I>>>) -> Result<(), AflError> {
        for stage in self.stages_mut() {
            stage.perform(&testcase)?;
        }
        Ok(())
    }
}

pub struct DefaultEngine<I>
where
    I: Input,
{
    feedbacks: Vec<Box<dyn Feedback<I>>>,
    stages: Vec<Box<dyn Stage<I>>>,
}

impl<I> Engine<I> for DefaultEngine<I>
where
    I: Input,
{
    fn feedbacks(&self) -> &Vec<Box<dyn Feedback<I>>> {
        &self.feedbacks
    }

    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>> {
        &mut self.feedbacks
    }

    fn stages(&self) -> &Vec<Box<dyn Stage<I>>> {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<I>>> {
        &mut self.stages
    }
}

impl<I> DefaultEngine<I>
where
    I: Input,
{
    pub fn new() -> Self {
        DefaultEngine {
            feedbacks: vec![],
            stages: vec![],
        }
    }

    pub fn new_rr() -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::new()))
    }
}

#[cfg(test)]
mod tests {
    use crate::corpus::{Corpus, InMemoryCorpus, Testcase};
    use crate::engines::{DefaultEngine, Engine};
    use crate::executors::inmemory::InMemoryExecutor;
    use crate::executors::{Executor, ExitKind};
    use crate::inputs::bytes::BytesInput;
    use crate::mutators::scheduled::{
        mutation_bitflip, ComposedByMutations, DefaultScheduledMutator,
    };
    use crate::stages::mutational::DefaultMutationalStage;

    use crate::utils::Xoshiro256StarRand;

    fn harness<I>(_executor: &dyn Executor<I>, _buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_engine() {
        let rand = Xoshiro256StarRand::preseeded_rr();

        let mut corpus = InMemoryCorpus::<BytesInput, _>::new(&rand);
        let testcase = Testcase::new_rr(BytesInput::new(vec![0; 4]));
        corpus.add(testcase);
        let executor = InMemoryExecutor::new_rr(harness);
        let mut engine = DefaultEngine::new();
        let mut mutator = DefaultScheduledMutator::new(&rand);
        mutator.add_mutation(mutation_bitflip);
        let stage = DefaultMutationalStage::new(&rand, &executor, mutator);
        engine.add_stage(Box::new(stage));
        engine.fuzz_one(&corpus.next().unwrap()).unwrap();
    }
}
