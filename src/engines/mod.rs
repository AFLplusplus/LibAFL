//! The engine is the core piece of every good fuzzer
extern crate alloc;

use alloc::rc::Rc;
use core::cell::RefCell;

use crate::corpus::Corpus;
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::stages::Stage;
use crate::AflError;

pub trait Engine<C, I>
where
    C: Corpus<I>,
    I: Input,
{
    fn feedbacks(&self) -> &Vec<Box<dyn Feedback<I>>>;

    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>>;

    fn add_feedback(&mut self, feedback: Box<dyn Feedback<I>>) {
        self.feedbacks_mut().push(feedback);
    }

    fn stages(&self) -> &Vec<Box<dyn Stage<C, I>>>;

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<C, I>>>;

    fn add_stage(&mut self, stage: Box<dyn Stage<C, I>>) {
        self.stages_mut().push(stage);
    }

    fn fuzz_one(&mut self, corpus: &mut C) -> Result<(), AflError> {
        for stage in self.stages_mut() {
            stage.perform(corpus)?;
        }
        Ok(())
    }
}

pub struct DefaultEngine<C, I>
where
    C: Corpus<I>,
    I: Input,
{
    feedbacks: Vec<Box<dyn Feedback<I>>>,
    stages: Vec<Box<dyn Stage<C, I>>>,
}

impl<C, I> Engine<C, I> for DefaultEngine<C, I>
where
    C: Corpus<I>,
    I: Input,
{
    fn feedbacks(&self) -> &Vec<Box<dyn Feedback<I>>> {
        &self.feedbacks
    }

    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>> {
        &mut self.feedbacks
    }

    fn stages(&self) -> &Vec<Box<dyn Stage<C, I>>> {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<C, I>>> {
        &mut self.stages
    }
}

impl<C, I> DefaultEngine<C, I>
where
    C: Corpus<I>,
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

    use alloc::rc::Rc;
    use core::cell::RefCell;

    use crate::corpus::{Corpus, InMemoryCorpus, Testcase};
    use crate::engines::{DefaultEngine, Engine};
    use crate::executors::inmemory::InMemoryExecutor;
    use crate::executors::{Executor, ExitKind};
    use crate::inputs::bytes::BytesInput;
    use crate::mutators::scheduled::{
        mutation_bitflip, ComposedByMutations, DefaultScheduledMutator,
    };
    use crate::stages::mutational::DefaultMutationalStage;
    use crate::utils::DefaultRand;

    fn harness<I>(_executor: &dyn Executor<I>, _buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_engine() {
        let rand: Rc<_> = DefaultRand::preseeded().into();

        let mut corpus = InMemoryCorpus::<BytesInput, _>::new(&rand);
        let testcase = Testcase::new_rr(vec![0; 4]);
        corpus.add(testcase);
        let executor: Rc<RefCell<InMemoryExecutor<BytesInput>>> = InMemoryExecutor::new_rr(harness);
        let mut engine = DefaultEngine::new();
        let mut mutator = DefaultScheduledMutator::new(&rand);
        mutator.add_mutation(mutation_bitflip);
        let stage = DefaultMutationalStage::new(&rand, &executor, mutator);
        engine.add_stage(Box::new(stage));
        for i in 0..1000 {
            engine
                .fuzz_one(&mut corpus)
                .expect(&format!("Error in iter {}", i));
        }
    }
}
