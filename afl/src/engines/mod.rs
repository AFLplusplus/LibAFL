//! The engine is the core piece of every good fuzzer

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt::Debug;
use core::marker::PhantomData;
use hashbrown::HashMap;

use crate::corpus::{Corpus, Testcase};
use crate::events::{Event, EventManager};
use crate::executors::Executor;
use crate::feedbacks::Feedback;
use crate::generators::Generator;
use crate::inputs::Input;
use crate::observers::Observer;
use crate::stages::Stage;
use crate::utils::{current_milliseconds, Rand};
use crate::AflError;

// TODO FeedbackMetadata to store histroy_map

pub trait StateMetadata: Debug {
    /// The name of this metadata - used to find it in the list of avaliable metadatas
    fn name(&self) -> &'static str;
}

pub trait State<C, E, I, R>
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

    fn start_time(&self) -> u64;
    fn set_start_time(&mut self, ms: u64);

    fn executions_over_seconds(&self) -> u64 {
        let elapsed = current_milliseconds() - self.start_time();
        if elapsed == 0 {
            return 0;
        }
        let elapsed = elapsed / 1000;
        if elapsed == 0 {
            0
        } else {
            (self.executions() as u64) / elapsed
        }
    }

    /// Get all the metadatas into an HashMap
    fn metadatas(&self) -> &HashMap<&'static str, Box<dyn StateMetadata>>;

    /// Get all the metadatas into an HashMap (mutable)
    fn metadatas_mut(&mut self) -> &mut HashMap<&'static str, Box<dyn StateMetadata>>;

    /// Add a metadata
    fn add_metadata(&mut self, meta: Box<dyn StateMetadata>) {
        self.metadatas_mut().insert(meta.name(), meta);
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
    fn evaluate_input(&mut self, input: &I) -> Result<u32, AflError> {
        self.executor_mut().reset_observers()?;
        self.executor_mut().run_target(&input)?;
        self.set_executions(self.executions() + 1);
        self.executor_mut().post_exec_observers()?;

        let mut fitness = 0;
        let observers = self.executor().observers();
        for feedback in self.feedbacks_mut() {
            fitness += feedback.is_interesting(&input, observers)?;
        }
        Ok(fitness)
    }

    /// Resets all current feedbacks
    fn discard_input(&mut self, input: &I) -> Result<(), AflError> {
        // TODO: This could probably be automatic in the feedback somehow?
        for feedback in self.feedbacks_mut() {
            feedback.discard_metadata(input)?;
        }
        Ok(())
    }

    /// Creates a new testcase, appending the metadata from each feedback
    fn input_to_testcase(&mut self, input: I, fitness: u32) -> Result<Testcase<I>, AflError> {
        let mut testcase = Testcase::new(input);
        testcase.set_fitness(fitness);
        for feedback in self.feedbacks_mut() {
            feedback.append_metadata(&mut testcase)?;
        }

        Ok(testcase)
    }

    /// Create a testcase from this input, if it's intersting
    fn testcase_if_interesting(
        &mut self,
        input: I,
        fitness: u32,
    ) -> Result<Option<Testcase<I>>, AflError> {
        if fitness > 0 {
            Ok(Some(self.input_to_testcase(input, fitness)?))
        } else {
            self.discard_input(&input)?;
            Ok(None)
        }
    }

    /// Adds this input to the corpus, if it's intersting
    fn add_if_interesting(
        &mut self,
        corpus: &mut C,
        input: I,
        fitness: u32,
    ) -> Result<Option<usize>, AflError> {
        if fitness > 0 {
            let testcase = self.input_to_testcase(input, fitness)?;
            Ok(Some(corpus.add(testcase)))
        } else {
            self.discard_input(&input)?;
            Ok(None)
        }
    }
}

pub fn generate_initial_inputs<S, G, C, E, I, R, EM>(
    rand: &mut R,
    state: &mut S,
    corpus: &mut C,
    generator: &mut G,
    events: &mut EM,
    num: usize,
) -> Result<(), AflError>
where
    S: State<C, E, I, R>,
    G: Generator<I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
    EM: EventManager<S, C, E, I, R>,
{
    for _ in 0..num {
        let input = generator.generate(rand)?;
        let fitness = state.evaluate_input(&input)?;
        state.add_if_interesting(corpus, input, fitness)?;
        events.fire(Event::LoadInitial {
            sender_id: 0,
            phantom: PhantomData,
        })?;
    }
    events.process(state, corpus)?;
    Ok(())
}

pub struct StdState<C, E, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    executions: usize,
    start_time: u64,
    metadatas: HashMap<&'static str, Box<dyn StateMetadata>>,
    // additional_corpuses: HashMap<&'static str, Box<dyn Corpus>>,
    observers: Vec<Rc<RefCell<dyn Observer>>>,
    feedbacks: Vec<Box<dyn Feedback<I>>>,
    executor: E,
    phantom: PhantomData<(C, R)>,
}

impl<C, E, I, R> State<C, E, I, R> for StdState<C, E, I, R>
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

    fn start_time(&self) -> u64 {
        self.start_time
    }
    fn set_start_time(&mut self, ms: u64) {
        self.start_time = ms
    }

    fn metadatas(&self) -> &HashMap<&'static str, Box<dyn StateMetadata>> {
        &self.metadatas
    }

    fn metadatas_mut(&mut self) -> &mut HashMap<&'static str, Box<dyn StateMetadata>> {
        &mut self.metadatas
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

impl<C, E, I, R> StdState<C, E, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
{
    pub fn new(executor: E) -> Self {
        Self {
            executions: 0,
            start_time: current_milliseconds(),
            metadatas: HashMap::default(),
            observers: vec![],
            feedbacks: vec![],
            executor: executor,
            phantom: PhantomData,
        }
    }
}

pub trait Engine<S, EM, E, C, I, R>
where
    S: State<C, E, I, R>,
    EM: EventManager<S, C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn stages(&self) -> &[Box<dyn Stage<S, EM, E, C, I, R>>];

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<S, EM, E, C, I, R>>>;

    fn add_stage(&mut self, stage: Box<dyn Stage<S, EM, E, C, I, R>>) {
        self.stages_mut().push(stage);
    }

    fn fuzz_one(
        &mut self,
        rand: &mut R,
        state: &mut S,
        corpus: &mut C,
        events: &mut EM,
    ) -> Result<usize, AflError> {
        let (testcase, idx) = corpus.next(rand)?;
        match testcase.input() {
            None => {
                // Load from disk.
                corpus.load_testcase(idx)?;
            }
            _ => (),
        };

        let input = corpus.get(idx).input().as_ref().unwrap();

        for stage in self.stages_mut() {
            stage.perform(rand, state, corpus, events, &input)?;
        }

        events.process(state, corpus)?;
        Ok(idx)
    }

    fn fuzz_loop(
        &mut self,
        rand: &mut R,
        state: &mut S,
        corpus: &mut C,
        events: &mut EM,
    ) -> Result<(), AflError> {
        let mut last = current_milliseconds();
        loop {
            self.fuzz_one(rand, state, corpus, events)?;
            let cur = current_milliseconds();
            if cur - last > 60 * 100 {
                last = cur;
                events.fire(Event::UpdateStats {
                    sender_id: 0,
                    new_execs: 1,
                    phantom: PhantomData,
                })?; // TODO self.new_execs});
            }
        }
    }
}

pub struct StdEngine<S, EM, E, C, I, R>
where
    S: State<C, E, I, R>,
    EM: EventManager<S, C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    stages: Vec<Box<dyn Stage<S, EM, E, C, I, R>>>,
    phantom: PhantomData<EM>,
}

impl<S, EM, E, C, I, R> Engine<S, EM, E, C, I, R> for StdEngine<S, EM, E, C, I, R>
where
    S: State<C, E, I, R>,
    EM: EventManager<S, C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn stages(&self) -> &[Box<dyn Stage<S, EM, E, C, I, R>>] {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<S, EM, E, C, I, R>>> {
        &mut self.stages
    }
}

impl<S, EM, E, C, I, R> StdEngine<S, EM, E, C, I, R>
where
    S: State<C, E, I, R>,
    EM: EventManager<S, C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    pub fn new() -> Self {
        Self {
            stages: vec![],
            phantom: PhantomData,
        }
    }
}

// TODO: no_std test
#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use alloc::boxed::Box;

    #[cfg(feature = "std")]
    use std::io::stderr;

    use crate::corpus::{Corpus, InMemoryCorpus, Testcase};
    use crate::engines::{Engine, StdEngine, StdState};
    #[cfg(feature = "std")]
    use crate::events::LoggerEventManager;
    use crate::executors::inmemory::InMemoryExecutor;
    use crate::executors::{Executor, ExitKind};
    use crate::inputs::bytes::BytesInput;
    use crate::mutators::{mutation_bitflip, ComposedByMutations, StdScheduledMutator};
    use crate::stages::mutational::StdMutationalStage;
    use crate::utils::StdRand;

    fn harness<I>(_executor: &dyn Executor<I>, _buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_engine() {
        let mut rand = StdRand::new(0);

        let mut corpus = InMemoryCorpus::<BytesInput, StdRand>::new();
        let testcase = Testcase::new(vec![0; 4]).into();
        corpus.add(testcase);

        let executor = InMemoryExecutor::<BytesInput>::new(harness);
        let mut state = StdState::new(executor);

        let mut events_manager = LoggerEventManager::new(stderr());

        let mut engine = StdEngine::new();
        let mut mutator = StdScheduledMutator::new();
        mutator.add_mutation(mutation_bitflip);
        let stage = StdMutationalStage::new(mutator);
        engine.add_stage(Box::new(stage));

        //

        for i in 0..1000 {
            engine
                .fuzz_one(&mut rand, &mut state, &mut corpus, &mut events_manager)
                .expect(&format!("Error in iter {}", i));
        }
    }
}
