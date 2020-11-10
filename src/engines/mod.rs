use crate::corpus::testcase::{Testcase, TestcaseMetadata};
use crate::corpus::Corpus;
use crate::executors::Executor;
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::stages::Stage;
use crate::AflError;

use core::cell::RefCell;
use std::rc::Rc;

pub trait Engine<I, C, E>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I, C>,
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

    fn executor(&self) -> &E;

    fn executor_mut(&mut self) -> &mut E;

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

impl<I, C, E> Engine<I, C, E> for DefaultEngine<I>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I, C>,
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
    pub fn new(executor: E) -> Self {
        DefaultEngine {
            feedbacks: vec![],
            stages: vec![],
        }
    }

    pub fn new_rr(executor: E) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Self::new(executor)))
    }
}

pub struct FuzzState<I, C>
where
    I: Input,
    C: Corpus<I>,
{

    corpus: C,
    current_input: Option<I>,

}

impl<I, C> FuzzState<I, C>
where
    I: Input,
    C: Corpus<I>,
{
    pub fn new(corpus: C) -> Self {
        Self{corpus: corpus, current_input: None}
    }
}


#[cfg(test)]
mod tests {
    use crate::corpus::{Corpus, InMemoryCorpus, Testcase};
    use crate::engines::{DefaultEngine, Engine, FuzzState};
    use crate::executors::inmemory::InMemoryExecutor;
    use crate::executors::{Executor, ExitKind};
    use crate::inputs::bytes::BytesInput;
    use crate::mutators::DefaultScheduledMutator;
    use crate::mutators::scheduled::mutation_bitflip;
    use crate::stages::mutational::DefaultMutationalStage;
    use crate::stages::Stage;
    use crate::utils::Xoshiro256StarRand;

    fn harness<I, C>(_executor: &dyn Executor<I, C>, _buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_engine() {
        let rand = Xoshiro256StarRand::preseeded_rr();

        let corpus = InMemoryCorpus::<BytesInput, _>::new(&rand);
        let testcase = Testcase::new_rr(BytesInput::new(vec![0; 4]));
        corpus.add(testcase);
        let executor = InMemoryExecutor::new(harness);
        let state = FuzzState::new(corpus);
        let engine = DefaultEngine::new(executor);
        let mutator = DefaultScheduledMutator::new(&rand);
        mutator.add_mutation(mutation_bitflip);
        let stage = DefaultMutationalStage::new(&rand, &engine, mutator);
        engine.add_stage(Box::new(stage));
        engine.fuzz_one(&corpus.next().unwrap()).unwrap();
    }
}
