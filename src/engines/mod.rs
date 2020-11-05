use crate::corpus::testcase::{Testcase, TestcaseMetadata};
use crate::corpus::Corpus;
use crate::executors::Executor;
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::stages::Stage;
use crate::AflError;

use std::cell::RefCell;
use std::rc::Rc;

pub trait Evaluator<I>
where
    I: Input,
{
    fn evaluate_input(
        &mut self,
        input: &mut I,
        entry: Rc<RefCell<Testcase<I>>>,
    ) -> Result<bool, AflError>;
}

pub trait Engine<'a, I, C, E>: Evaluator<I>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{
    fn feedbacks(&self) -> &Vec<Box<dyn Feedback<I>>>;

    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>>;

    fn add_feedback(&mut self, feedback: Box<dyn Feedback<I>>) {
        self.feedbacks_mut().push(feedback);
    }

    fn stages(&self) -> &Vec<Box<dyn Stage<'a, I, E = Self>>>;

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<'a, I, E = Self>>>;

    fn add_stage(&mut self, stage: Box<dyn Stage<'a, I, E = Self>>) {
        self.stages_mut().push(stage);
    }

    fn corpus(&self) -> &C;

    fn corpus_mut(&mut self) -> &mut C;

    fn executor(&self) -> &E;

    fn executor_mut(&mut self) -> &mut E;

    fn fuzz_one(&mut self) -> Result<(), AflError> {
        let entry = self.corpus_mut().get()?;
        for stage in self.stages_mut() {
            stage.perform(entry.clone())?;
        }
        Ok(())
    }

    fn evaluate_input_engine(
        &mut self,
        input: &mut I,
        _entry: Rc<RefCell<Testcase<I>>>,
    ) -> Result<bool, AflError> {
        self.executor_mut().reset_observers()?;
        self.executor_mut().run_target(input)?;
        self.executor_mut().post_exec_observers()?;

        let mut metadatas: Vec<Box<dyn TestcaseMetadata>> = vec![];
        let mut rate_acc = 0;
        for feedback in self.feedbacks_mut() {
            let (rate, meta) = feedback.is_interesting(input);
            rate_acc += rate;
            if let Some(m) = meta {
                metadatas.push(m);
            }
        }

        if rate_acc >= 25 {
            let new_entry = Rc::new(RefCell::new(Testcase::<I>::new(input.clone())));
            for meta in metadatas {
                new_entry.borrow_mut().add_metadata(meta);
            }
            self.corpus_mut().add(new_entry);

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub struct DefaultEngine<'a, I, C, E>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{
    feedbacks: Vec<Box<dyn Feedback<I>>>,
    stages: Vec<Box<dyn Stage<'a, I, E = Self>>>,
    executor: &'a mut E,
    corpus: &'a mut C,
}

impl<'a, I, C, E> Evaluator<I> for DefaultEngine<'a, I, C, E>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{
    fn evaluate_input(
        &mut self,
        input: &mut I,
        entry: Rc<RefCell<Testcase<I>>>,
    ) -> Result<bool, AflError> {
        self.evaluate_input_engine(input, entry)
    }
}

impl<'a, I, C, E> Engine<'a, I, C, E> for DefaultEngine<'a, I, C, E>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{
    fn feedbacks(&self) -> &Vec<Box<dyn Feedback<I>>> {
        &self.feedbacks
    }

    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>> {
        &mut self.feedbacks
    }

    fn stages(&self) -> &Vec<Box<dyn Stage<'a, I, E = Self>>> {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<'a, I, E = Self>>> {
        &mut self.stages
    }

    fn corpus(&self) -> &C {
        self.corpus
    }

    fn corpus_mut(&mut self) -> &mut C {
        self.corpus
    }

    fn executor(&self) -> &E {
        self.executor
    }

    fn executor_mut(&mut self) -> &mut E {
        self.executor
    }
}

impl<'a, I, C, E> DefaultEngine<'a, I, C, E>
where
    I: Input,
    C: Corpus<I>,
    E: Executor<I>,
{
    pub fn new(corpus: &'a mut C, executor: &'a mut E) -> Self {
        DefaultEngine {
            feedbacks: vec![],
            stages: vec![],
            corpus: corpus,
            executor: executor,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::corpus::testcase::Testcase;
    use crate::corpus::InMemoryCorpus;
    use crate::engines::{DefaultEngine, Engine};
    use crate::executors::inmemory::InMemoryExecutor;
    use crate::executors::{Executor, ExitKind};
    use crate::inputs::bytes::BytesInput;
    use crate::stages::mutational::DefaultMutationalStage;
    use crate::utils::Xoshiro256StarRand;

    use std::cell::RefCell;
    use std::path::PathBuf;
    use std::rc::Rc;

    fn harness<I>(_executor: &dyn Executor<I>, buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_engine() {
        let mut rand = Xoshiro256StarRand::new();
        let mut corpus = InMemoryCorpus::<BytesInput, _>::new(&mut rand);
        let mut executor = InMemoryExecutor::new(harness);
        let mut engine = DefaultEngine::new(&mut corpus, &mut executor);
        let mut rand1 = Xoshiro256StarRand::new();
        let mut stage = Box::new(DefaultMutationalStage::new(&mut rand1, &mut engine));
        engine.add_stage(stage);
        engine.fuzz_one().unwrap();
        let mut stage1 = Box::new(DefaultMutationalStage::new(&mut rand1, &mut engine));
        engine.fuzz_one().unwrap();
    }
}
