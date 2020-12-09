//! The engine is the core piece of every good fuzzer

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;
use hashbrown::HashMap;

use crate::corpus::{Corpus, Testcase};
use crate::events::{Event, EventManager};
use crate::executors::Executor;
use crate::feedbacks::Feedback;
use crate::generators::Generator;
use crate::inputs::Input;
use crate::stages::Stage;
use crate::utils::{current_milliseconds, Rand};
use crate::AflError;

pub trait StateMetadata: Debug {
    /// The name of this metadata - used to find it in the list of avaliable metadatas
    fn name(&self) -> &'static str;
}

pub struct State<I, R>
where
    I: Input,
    R: Rand,
{
    executions: usize,
    start_time: u64,
    metadatas: HashMap<&'static str, Box<dyn StateMetadata>>,
    // additional_corpuses: HashMap<&'static str, Box<dyn Corpus>>,
    feedbacks: Vec<Box<dyn Feedback<I>>>,
    phantom: PhantomData<R>,
}

impl<I, R> State<I, R>
where
    I: Input,
    R: Rand,
{
    /// Get executions
    pub fn executions(&self) -> usize {
        self.executions
    }

    /// Set executions
    pub fn set_executions(&mut self, executions: usize) {
        self.executions = executions
    }

    pub fn start_time(&self) -> u64 {
        self.start_time
    }
    pub fn set_start_time(&mut self, ms: u64) {
        self.start_time = ms
    }

    pub fn executions_over_seconds(&self) -> u64 {
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
    pub fn metadatas(&self) -> &HashMap<&'static str, Box<dyn StateMetadata>> {
        &self.metadatas
    }

    /// Get all the metadatas into an HashMap (mutable)
    pub fn metadatas_mut(&mut self) -> &mut HashMap<&'static str, Box<dyn StateMetadata>> {
        &mut self.metadatas
    }

    /// Add a metadata
    pub fn add_metadata(&mut self, meta: Box<dyn StateMetadata>) {
        self.metadatas_mut().insert(meta.name(), meta);
    }

    /// Returns vector of feebacks
    pub fn feedbacks(&self) -> &[Box<dyn Feedback<I>>] {
        &self.feedbacks
    }

    /// Returns vector of feebacks (mutable)
    pub fn feedbacks_mut(&mut self) -> &mut Vec<Box<dyn Feedback<I>>> {
        &mut self.feedbacks
    }

    /// Adds a feedback
    pub fn add_feedback(&mut self, feedback: Box<dyn Feedback<I>>) {
        self.feedbacks_mut().push(feedback);
    }

    // TODO move some of these, like evaluate_input, to FuzzingEngine

    /// Runs the input and triggers observers and feedback
    pub fn evaluate_input<E>(&mut self, input: &I, executor: &mut E) -> Result<u32, AflError>
    where
        E: Executor<I>,
    {
        executor.reset_observers()?;
        executor.run_target(&input)?;
        self.set_executions(self.executions() + 1);
        executor.post_exec_observers()?;

        let mut fitness = 0;
        let observers = executor.observers();
        for feedback in self.feedbacks_mut() {
            fitness += feedback.is_interesting(&input, observers)?;
        }
        Ok(fitness)
    }

    /// Resets all current feedbacks
    pub fn discard_input(&mut self, input: &I) -> Result<(), AflError> {
        // TODO: This could probably be automatic in the feedback somehow?
        for feedback in self.feedbacks_mut() {
            feedback.discard_metadata(input)?;
        }
        Ok(())
    }

    /// Creates a new testcase, appending the metadata from each feedback
    pub fn input_to_testcase(&mut self, input: I, fitness: u32) -> Result<Testcase<I>, AflError> {
        let mut testcase = Testcase::new(input);
        testcase.set_fitness(fitness);
        for feedback in self.feedbacks_mut() {
            feedback.append_metadata(&mut testcase)?;
        }

        Ok(testcase)
    }

    /// Create a testcase from this input, if it's intersting
    pub fn testcase_if_interesting(
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
    pub fn add_if_interesting<C>(
        &mut self,
        corpus: &mut C,
        input: I,
        fitness: u32,
    ) -> Result<Option<usize>, AflError>
    where
        C: Corpus<I, R>,
    {
        if fitness > 0 {
            let testcase = self.input_to_testcase(input, fitness)?;
            Ok(Some(corpus.add(testcase)))
        } else {
            self.discard_input(&input)?;
            Ok(None)
        }
    }

    pub fn generate_initial_inputs<G, C, E, FE, EM>(
        &mut self,
        rand: &mut R,
        corpus: &mut C,
        generator: &mut G,
        engine: &mut Engine<E, I>,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), AflError>
    where
        G: Generator<I, R>,
        C: Corpus<I, R>,
        E: Executor<I>,
        EM: EventManager<C, E, I, R>,
    {
        for _ in 0..num {
            let input = generator.generate(rand)?;
            let fitness = self.evaluate_input(&input, engine.executor_mut())?;
            self.add_if_interesting(corpus, input, fitness)?;
            manager.fire(
                Event::LoadInitial {
                    sender_id: 0,
                    phantom: PhantomData,
                },
                self,
                corpus,
            )?;
        }
        manager.process(self, corpus)?;
        Ok(())
    }

    pub fn new() -> Self {
        Self {
            executions: 0,
            start_time: current_milliseconds(),
            metadatas: HashMap::default(),
            feedbacks: vec![],
            phantom: PhantomData,
        }
    }
}

pub struct Engine<E, I>
where
    E: Executor<I>,
    I: Input,
{
    executor: E,
    phantom: PhantomData<I>,
}

impl<E, I> Engine<E, I>
where
    E: Executor<I>,
    I: Input,
{
    /// Return the executor
    pub fn executor(&self) -> &E {
        &self.executor
    }

    /// Return the executor (mutable)
    pub fn executor_mut(&mut self) -> &mut E {
        &mut self.executor
    }

    // TODO additional executors, Vec<Box<dyn Executor<I>>>

    pub fn new(executor: E) -> Self {
        Self {
            executor: executor,
            phantom: PhantomData,
        }
    }
}

pub trait Fuzzer<EM, E, C, I, R>
where
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn stages(&self) -> &[Box<dyn Stage<EM, E, C, I, R>>];

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<EM, E, C, I, R>>>;

    fn add_stage(&mut self, stage: Box<dyn Stage<EM, E, C, I, R>>) {
        self.stages_mut().push(stage);
    }

    fn fuzz_one(
        &mut self,
        rand: &mut R,
        state: &mut State<I, R>,
        corpus: &mut C,
        engine: &mut Engine<E, I>,
        manager: &mut EM,
    ) -> Result<usize, AflError> {
        let (_, idx) = corpus.next(rand)?;

        for stage in self.stages_mut() {
            stage.perform(rand, state, corpus, engine, manager, idx)?;
        }

        manager.process(state, corpus)?;
        Ok(idx)
    }

    fn fuzz_loop(
        &mut self,
        rand: &mut R,
        state: &mut State<I, R>,
        corpus: &mut C,
        engine: &mut Engine<E, I>,
        manager: &mut EM,
    ) -> Result<(), AflError> {
        let mut last = current_milliseconds();
        loop {
            self.fuzz_one(rand, state, corpus, engine, manager)?;
            let cur = current_milliseconds();
            if cur - last > 60 * 100 {
                last = cur;
                manager.fire(
                    Event::UpdateStats {
                        sender_id: 0,
                        new_execs: 1,
                        phantom: PhantomData,
                    },
                    state,
                    corpus,
                )?; // TODO self.new_execs});
            }
        }
    }
}

pub struct StdFuzzer<EM, E, C, I, R>
where
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    stages: Vec<Box<dyn Stage<EM, E, C, I, R>>>,
}

impl<EM, E, C, I, R> Fuzzer<EM, E, C, I, R> for StdFuzzer<EM, E, C, I, R>
where
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn stages(&self) -> &[Box<dyn Stage<EM, E, C, I, R>>] {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut Vec<Box<dyn Stage<EM, E, C, I, R>>> {
        &mut self.stages
    }
}

impl<EM, E, C, I, R> StdFuzzer<EM, E, C, I, R>
where
    EM: EventManager<C, E, I, R>,
    E: Executor<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    pub fn new() -> Self {
        Self { stages: vec![] }
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
    use crate::engines::{Engine, Fuzzer, State, StdFuzzer};
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
        let mut state = State::new();

        let mut events_manager = LoggerEventManager::new(stderr());
        let mut engine = Engine::new(executor);
        let mut mutator = StdScheduledMutator::new();
        mutator.add_mutation(mutation_bitflip);
        let stage = StdMutationalStage::new(mutator);
        let mut fuzzer = StdFuzzer::new();
        fuzzer.add_stage(Box::new(stage));

        //

        for i in 0..1000 {
            fuzzer
                .fuzz_one(
                    &mut rand,
                    &mut state,
                    &mut corpus,
                    &mut engine,
                    &mut events_manager,
                )
                .expect(&format!("Error in iter {}", i));
        }
    }
}
