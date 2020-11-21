//! The engine is the core piece of every good fuzzer

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt::Debug;

use crate::corpus::{Corpus, Testcase};
use crate::executors::Executor;
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::observers::Observer;
use crate::stages::Stage;
use crate::AflError;

pub trait StateMetadata: Debug {}

pub trait State<C, E, I>
where
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
{
    /// Get executions
    fn executions(&self) -> usize;

    /// Set executions
    fn set_executions(&mut self, executions: usize);

    /// Get the linked observers
    fn observers(&self) -> &[Rc<RefCell<dyn Observer>>];

    /// Get the linked observers
    fn observers_mut(&mut self) -> &mut Vec<Rc<RefCell<dyn Observer>>>;

    /// Add a linked observer
    fn add_observer(&mut self, observer: Rc<RefCell<dyn Observer>>) {
        self.observers_mut().push(observer);
    }

    /// Reset the state of all the observes linked to this executor
    fn reset_observers(&mut self) -> Result<(), AflError> {
        for observer in self.observers() {
            observer.borrow_mut().reset()?;
        }
        Ok(())
    }

    /// Run the post exec hook for all the observes linked to this executor
    fn post_exec_observers(&mut self) -> Result<(), AflError> {
        self.observers()
            .iter()
            .map(|x| x.borrow_mut().post_exec())
            .fold(Ok(()), |acc, x| if x.is_err() { x } else { acc })
    }

    /// Returns vector of feebacks
    fn feedbacks(&self) -> &[Box<dyn Feedback<I>>];

    /// Returns vector of feebacks (mutable)
    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>>;

    /// Adds a feedback
    fn add_feedback(&mut self, feedback: Box<dyn Feedback<I>>) {
        self.feedbacks_mut().push(feedback);
    }

    /// Return the corpus
    fn corpus(&self) -> &C;

    /// Return the corpus (mutable)
    fn corpus_mut(&mut self) -> &mut C;

    /// Return the executor
    fn executor(&self) -> &E;

    /// Return the executor (mutable)
    fn executor_mut(&mut self) -> &mut E;

    /// Runs the input and triggers observers and feedback
    fn evaluate_input(&mut self, input: &I) -> Result<bool, AflError> {
        self.reset_observers()?;
        self.executor_mut().run_target(input)?;
        self.set_executions(self.executions() + 1);
        self.post_exec_observers()?;

        let mut rate_acc = 0;
        for feedback in self.feedbacks_mut() {
            rate_acc += feedback.is_interesting(input)?;
        }

        if rate_acc >= 25 {
            let testcase = Rc::new(RefCell::new(Testcase::new(input.clone())));
            for feedback in self.feedbacks_mut() {
                feedback.append_metadata(testcase.clone())?;
            }
            Ok(true)
        } else {
            for feedback in self.feedbacks_mut() {
                feedback.discard_metadata()?;
            }
            Ok(false)
        }
    }
}

pub struct DefaultState<C, E, I>
where
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
{
    executions: usize,
    observers: Vec<Rc<RefCell<dyn Observer>>>,
    feedbacks: Vec<Box<dyn Feedback<I>>>,
    corpus: C,
    executor: E,
}

impl<C, E, I> State<C, E, I> for DefaultState<C, E, I>
where
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
{
    fn executions(&self) -> usize {
        self.executions
    }

    fn set_executions(&mut self, executions: usize) {
        self.executions = executions
    }

    fn observers(&self) -> &[Rc<RefCell<dyn Observer>>] {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut Vec<Rc<RefCell<dyn Observer>>> {
        &mut self.observers
    }

    fn feedbacks(&self) -> &[Box<dyn Feedback<I>>] {
        &self.feedbacks
    }

    fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>> {
        &mut self.feedbacks
    }

    fn corpus(&self) -> &C {
        &self.corpus
    }

    fn corpus_mut(&mut self) -> &mut C {
        &mut self.corpus
    }

    fn executor(&self) -> &E {
        &self.executor
    }

    fn executor_mut(&mut self) -> &mut E {
        &mut self.executor
    }
}

impl<C, E, I> DefaultState<C, E, I>
where
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
{
    pub fn new(corpus: C, executor: E) -> Self {
        DefaultState {
            executions: 0,
            observers: vec![],
            feedbacks: vec![],
            corpus: corpus,
            executor: executor,
        }
    }
}

pub trait Engine<S, C, E, I>
where
    S: State<C, E, I>,
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
{
    fn stages(&self) -> &[Box<dyn Stage<S, C, E, I>>];

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<S, C, E, I>>>;

    fn add_stage(&mut self, stage: Box<dyn Stage<S, C, E, I>>) {
        self.stages_mut().push(stage);
    }

    fn fuzz_one(&mut self, state: &mut S) -> Result<usize, AflError> {
        let (testcase, idx) = state.corpus_mut().next()?;
        #[cfg(feature = "std")]
        println!("Cur entry: {}\tExecutions: {}", idx, state.executions());
        for stage in self.stages_mut() {
            stage.perform(testcase.clone(), state)?;
        }
        Ok(idx)
    }
}

pub struct DefaultEngine<S, C, E, I>
where
    S: State<C, E, I>,
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
{
    stages: Vec<Box<dyn Stage<S, C, E, I>>>,
}

impl<S, C, E, I> Engine<S, C, E, I> for DefaultEngine<S, C, E, I>
where
    S: State<C, E, I>,
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
{
    fn stages(&self) -> &[Box<dyn Stage<S, C, E, I>>] {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<S, C, E, I>>> {
        &mut self.stages
    }
}

impl<S, C, E, I> DefaultEngine<S, C, E, I>
where
    S: State<C, E, I>,
    C: Corpus<I>,
    E: Executor<I>,
    I: Input,
{
    pub fn new() -> Self {
        DefaultEngine { stages: vec![] }
    }
}

#[cfg(test)]
mod tests {

    use alloc::boxed::Box;

    use crate::corpus::{Corpus, InMemoryCorpus, Testcase};
    use crate::engines::{DefaultEngine, DefaultState, Engine};
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
        let rand = DefaultRand::new(0).into();

        let mut corpus = InMemoryCorpus::<BytesInput, _>::new(&rand);
        let testcase = Testcase::new(vec![0; 4]).into();
        corpus.add(testcase);

        let executor = InMemoryExecutor::<BytesInput>::new(harness);
        let mut state = DefaultState::new(corpus, executor);

        let mut engine = DefaultEngine::new();
        let mut mutator = DefaultScheduledMutator::new(&rand);
        mutator.add_mutation(mutation_bitflip);
        let stage = DefaultMutationalStage::new(&rand, mutator);
        engine.add_stage(Box::new(stage));

        //

        for i in 0..1000 {
            engine
                .fuzz_one(&mut state)
                .expect(&format!("Error in iter {}", i));
        }
    }
}
