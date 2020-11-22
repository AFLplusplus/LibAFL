//! The engine is the core piece of every good fuzzer

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt::Debug;

use hashbrown::HashMap;

use crate::corpus::{Corpus, HasCorpus, Testcase};
use crate::events::EventManager;
use crate::executors::Executor;
use crate::feedbacks::Feedback;
use crate::inputs::Input;
use crate::observers::Observer;
use crate::stages::Stage;
use crate::utils::{HasRand, Rand};
use crate::AflError;

// TODO FeedbackMetadata to store histroy_map

pub trait StateMetadata: Debug {
    /// The name of this metadata - used to find it in the list of avaliable metadatas
    fn name(&self) -> &'static str;
}

pub trait State<C, E, I, R>: HasCorpus<C, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    /// Get executions
    fn executions(&self) -> usize;

    /// Set executions
    fn set_executions(&mut self, executions: usize);

    /// Get all the metadatas into an HashMap
    fn metadatas(&self) -> &HashMap<&'static str, Box<dyn StateMetadata>>;

    /// Get all the metadatas into an HashMap (mutable)
    fn metadatas_mut(&mut self) -> &mut HashMap<&'static str, Box<dyn StateMetadata>>;

    /// Add a metadata
    fn add_metadata(&mut self, meta: Box<dyn StateMetadata>) {
        self.metadatas_mut().insert(meta.name(), meta);
    }

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

pub struct DefaultState<C, E, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    executions: usize,
    metadatas: HashMap<&'static str, Box<dyn StateMetadata>>,
    // additional_corpuses: HashMap<&'static str, Box<dyn Corpus>>,
    observers: Vec<Rc<RefCell<dyn Observer>>>,
    feedbacks: Vec<Box<dyn Feedback<I>>>,
    corpus: C,
    executor: E,
}

impl<C, E, I, R> HasCorpus<C, I, R> for DefaultState<C, E, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    fn corpus(&self) -> &C {
        &self.corpus
    }

    /// Get thecorpus field (mutable)
    fn corpus_mut(&mut self) -> &mut C {
        &mut self.corpus
    }
}

impl<C, E, I, R> State<C, E, I, R> for DefaultState<C, E, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    fn executions(&self) -> usize {
        self.executions
    }

    fn set_executions(&mut self, executions: usize) {
        self.executions = executions
    }

    fn metadatas(&self) -> &HashMap<&'static str, Box<dyn StateMetadata>> {
        &self.metadatas
    }

    fn metadatas_mut(&mut self) -> &mut HashMap<&'static str, Box<dyn StateMetadata>> {
        &mut self.metadatas
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

    fn executor(&self) -> &E {
        &self.executor
    }

    fn executor_mut(&mut self) -> &mut E {
        &mut self.executor
    }
}

impl<C, E, I, R> DefaultState<C, E, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    pub fn new(corpus: C, executor: E) -> Self {
        DefaultState {
            executions: 0,
            metadatas: HashMap::default(),
            observers: vec![],
            feedbacks: vec![],
            corpus: corpus,
            executor: executor,
        }
    }
}

pub trait Engine<S, C, E, EM, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    EM: EventManager,
    I: Input,
    R: Rand,
{
    fn stages(&self) -> &[Box<dyn Stage<S, C, E, I, R>>];

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<S, C, E, I, R>>>;

    fn add_stage(&mut self, stage: Box<dyn Stage<S, C, E, I, R>>) {
        self.stages_mut().push(stage);
    }

    fn fuzz_one(
        &mut self,
        rand: &mut R,
        state: &mut S,
        events_manager: &mut EM,
    ) -> Result<usize, AflError> {
        let (testcase, idx) = state.corpus_mut().next(rand)?;
        println!("Cur entry: {}\tExecutions: {}", idx, state.executions());
        for stage in self.stages_mut() {
            stage.perform(testcase.clone(), state)?;
        }
        Ok(idx)
    }
}

pub struct DefaultEngine<S, C, E, EM, I, R>
where
    S: State<C, E, EM, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    EM: EventManager,
    I: Input,
    R: Rand,
{
    stages: Vec<Box<dyn Stage<S, C, E, I, R>>>,
}

impl<S, C, E, EM, I, R> Engine<S, C, E, EM, I, R> for DefaultEngine<S, C, E, EM, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    EM: EventManager,
    I: Input,
    R: Rand,
{
    fn stages(&self) -> &[Box<dyn Stage<S, C, E, I, R>>] {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<S, C, E, I, R>>> {
        &mut self.stages
    }
}

impl<S, C, E, EM, I, R> DefaultEngine<S, C, E, EM, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    EM: EventManager,
    I: Input,
    R: Rand,
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
    use crate::events::LoggerEventManager;
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
        let mut corpus = InMemoryCorpus::<BytesInput, DefaultRand>::new();
        let testcase = Testcase::new(vec![0; 4]).into();
        corpus.add(testcase);

        let executor = InMemoryExecutor::<BytesInput>::new(harness);
        let events = LoggerEventManager::new();
        let rand = DefaultRand::new(0);

        let mut state = DefaultState::new(corpus, executor, events, rand);

        let mut engine = DefaultEngine::new();
        let mut mutator = DefaultScheduledMutator::new();
        mutator.add_mutation(mutation_bitflip);
        let stage = DefaultMutationalStage::new(mutator);
        engine.add_stage(Box::new(stage));

        //

        for i in 0..1000 {
            engine
                .fuzz_one(&mut state)
                .expect(&format!("Error in iter {}", i));
        }
    }
}
