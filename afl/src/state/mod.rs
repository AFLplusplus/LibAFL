//! The fuzzer, and state are the core pieces of every good fuzzer

use core::{fmt::Debug, marker::PhantomData};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    corpus::{Corpus, Testcase},
    events::EventManager,
    executors::{Executor, HasObservers},
    feedbacks::FeedbacksTuple,
    generators::Generator,
    inputs::Input,
    observers::ObserversTuple,
    serde_anymap::{SerdeAny, SerdeAnyMap},
    stages::StagesTuple,
    utils::{current_milliseconds, Rand},
    AflError,
};

#[cfg(feature = "std")]
use crate::inputs::bytes::BytesInput;

pub trait StateMetadata: Debug {
    /// The name of this metadata - used to find it in the list of avaliable metadatas
    fn name(&self) -> &'static str;
}

/// The state a fuzz run.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "FT: serde::de::DeserializeOwned")]
pub struct State<I, R, FT>
where
    I: Input,
    FT: FeedbacksTuple<I>,
{
    /// How many times the executor ran the harness/target
    executions: usize,
    /// At what time the fuzzing started
    start_time: u64,
    /// Metadata stored for this state by one of the components
    metadatas: SerdeAnyMap,
    // additional_corpuses, maybe another TupleList?
    // Feedbacks used to evaluate an input
    feedbacks: FT,
    phantom: PhantomData<(R, I)>,
}

#[cfg(feature = "std")]
impl<R, FT> State<BytesInput, R, FT>
where
    R: Rand,
    FT: FeedbacksTuple<BytesInput>,
{
    pub fn load_from_directory<G, C, E, OT, EM>(
        &mut self,
        executor: &mut E,
        corpus: &mut C,
        generator: &mut G,
        manager: &mut EM,
        in_dir: &Path,
    ) -> Result<(), AflError>
    where
        G: Generator<BytesInput, R>,
        C: Corpus<BytesInput, R>,
        E: Executor<BytesInput> + HasObservers<OT>,
        OT: ObserversTuple,
        EM: EventManager<BytesInput>,
    {
        for entry in fs::read_dir(in_dir)? {
            let entry = entry?;
            let path = entry.path();
            let attributes = fs::metadata(&path);

            if !attributes.is_ok() {
                continue;
            }

            let attr = attributes?;

            if attr.is_file() && attr.len() > 0 {
                println!("Loading file {:?} ...", &path);
                let bytes = fs::read(&path)?;
                let input = BytesInput::new(bytes);
                let fitness = self.evaluate_input(&input, executor, corpus, manager)?;
                if self.add_if_interesting(corpus, input, fitness)?.is_none() {
                    println!("File {:?} was not interesting, skipped.", &path);
                }
            } else if attr.is_dir() {
                self.load_from_directory(executor, corpus, generator, manager, &path)?;
            }
        }

        Ok(())
    }

    pub fn load_initial_inputs<G, C, E, OT, EM>(
        &mut self,
        executor: &mut E,
        corpus: &mut C,
        generator: &mut G,
        manager: &mut EM,
        in_dirs: &[PathBuf],
    ) -> Result<(), AflError>
    where
        G: Generator<BytesInput, R>,
        C: Corpus<BytesInput, R>,
        E: Executor<BytesInput> + HasObservers<OT>,
        OT: ObserversTuple,
        EM: EventManager<BytesInput>,
    {
        for in_dir in in_dirs {
            self.load_from_directory(executor, corpus, generator, manager, in_dir)?;
        }
        manager.log(
            0,
            format!("Loaded {} initial testcases.", corpus.count()), // get corpus count
        )?;
        manager.process(self, corpus)?;
        Ok(())
    }
}

impl<I, R, FT> State<I, R, FT>
where
    I: Input,
    R: Rand,
    FT: FeedbacksTuple<I>,
{
    /// Get executions
    #[inline]
    pub fn executions(&self) -> usize {
        self.executions
    }

    /// Set executions
    #[inline]
    pub fn set_executions(&mut self, executions: usize) {
        self.executions = executions
    }

    #[inline]
    pub fn start_time(&self) -> u64 {
        self.start_time
    }
    #[inline]
    pub fn set_start_time(&mut self, ms: u64) {
        self.start_time = ms
    }

    // TODO as this is done in the event manager, we can remove it
    #[inline]
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
    #[inline]
    pub fn metadatas(&self) -> &SerdeAnyMap {
        &self.metadatas
    }

    /// Get all the metadatas into an HashMap (mutable)
    #[inline]
    pub fn metadatas_mut(&mut self) -> &mut SerdeAnyMap {
        &mut self.metadatas
    }

    /// Add a metadata
    #[inline]
    pub fn add_metadata<M>(&mut self, meta: M)
    where
        M: SerdeAny,
    {
        self.metadatas.insert(meta);
    }

    /// Returns vector of feebacks
    #[inline]
    pub fn feedbacks(&self) -> &FT {
        &self.feedbacks
    }

    /// Returns vector of feebacks (mutable)
    #[inline]
    pub fn feedbacks_mut(&mut self) -> &mut FT {
        &mut self.feedbacks
    }

    // TODO move some of these, like evaluate_input, to FuzzingEngine
    #[inline]
    pub fn is_interesting<OT>(&mut self, input: &I, observers: &OT) -> Result<u32, AflError>
    where
        OT: ObserversTuple,
    {
        Ok(self.feedbacks_mut().is_interesting_all(input, observers)?)
    }

    /// Runs the input and triggers observers and feedback
    pub fn evaluate_input<C, E, EM, OT>(
        &mut self,
        input: &I,
        executor: &mut E,
        corpus: &C,
        event_mgr: &mut EM,
    ) -> Result<u32, AflError>
    where
        E: Executor<I> + HasObservers<OT>,
        OT: ObserversTuple,
        C: Corpus<I, R>,
        EM: EventManager<I>,
    {
        executor.pre_exec_observers()?;

        executor.pre_exec(&self, corpus, event_mgr, input)?;
        executor.run_target(input)?;
        executor.post_exec(&self, corpus, event_mgr, input)?;

        self.set_executions(self.executions() + 1);
        executor.post_exec_observers()?;

        let observers = executor.observers();
        let fitness = self.feedbacks_mut().is_interesting_all(&input, observers)?;
        Ok(fitness)
    }

    /// Resets all current feedbacks
    #[inline]
    pub fn discard_input(&mut self, input: &I) -> Result<(), AflError> {
        // TODO: This could probably be automatic in the feedback somehow?
        self.feedbacks_mut().discard_metadata_all(&input)
    }

    /// Creates a new testcase, appending the metadata from each feedback
    #[inline]
    pub fn input_to_testcase(&mut self, input: I, fitness: u32) -> Result<Testcase<I>, AflError> {
        let mut testcase = Testcase::new(input);
        testcase.set_fitness(fitness);
        self.feedbacks_mut().append_metadata_all(&mut testcase)?;
        Ok(testcase)
    }

    /// Create a testcase from this input, if it's intersting
    #[inline]
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
    #[inline]
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

    pub fn generate_initial_inputs<G, C, E, OT, EM>(
        &mut self,
        rand: &mut R,
        executor: &mut E,
        corpus: &mut C,
        generator: &mut G,
        manager: &mut EM,
        num: usize,
    ) -> Result<(), AflError>
    where
        G: Generator<I, R>,
        C: Corpus<I, R>,
        E: Executor<I> + HasObservers<OT>,
        OT: ObserversTuple,
        EM: EventManager<I>,
    {
        let mut added = 0;
        for _ in 0..num {
            let input = generator.generate(rand)?;
            let fitness = self.evaluate_input(&input, executor, corpus, manager)?;
            if !self.add_if_interesting(corpus, input, fitness)?.is_none() {
                added += 1;
            }
        }
        manager.log(
            0,
            format!("Loaded {} over {} initial testcases", added, num),
        )?;
        manager.process(self, corpus)?;
        Ok(())
    }

    pub fn new(feedbacks: FT) -> Self {
        Self {
            executions: 0,
            start_time: current_milliseconds(),
            metadatas: SerdeAnyMap::default(),
            feedbacks: feedbacks,
            phantom: PhantomData,
        }
    }
}

pub trait Fuzzer<ST, EM, E, OT, FT, C, I, R>
where
    ST: StagesTuple<EM, E, OT, FT, C, I, R>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn stages(&self) -> &ST;

    fn stages_mut(&mut self) -> &mut ST;

    fn fuzz_one(
        &mut self,
        rand: &mut R,
        executor: &mut E,
        state: &mut State<I, R, FT>,
        corpus: &mut C,
        manager: &mut EM,
    ) -> Result<usize, AflError> {
        let (_, idx) = corpus.next(rand)?;

        self.stages_mut()
            .perform_all(rand, executor, state, corpus, manager, idx)?;

        manager.process(state, corpus)?;
        Ok(idx)
    }

    fn fuzz_loop(
        &mut self,
        rand: &mut R,
        executor: &mut E,
        state: &mut State<I, R, FT>,
        corpus: &mut C,
        manager: &mut EM,
    ) -> Result<(), AflError> {
        let mut last = current_milliseconds();
        loop {
            self.fuzz_one(rand, executor, state, corpus, manager)?;
            let cur = current_milliseconds();
            if cur - last > 60 * 100 {
                last = cur;
                manager.update_stats(state.executions(), state.executions_over_seconds())?;
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct StdFuzzer<ST, EM, E, OT, FT, C, I, R>
where
    ST: StagesTuple<EM, E, OT, FT, C, I, R>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    stages: ST,
    phantom: PhantomData<(EM, E, OT, FT, C, I, R)>,
}

impl<ST, EM, E, OT, FT, C, I, R> Fuzzer<ST, EM, E, OT, FT, C, I, R>
    for StdFuzzer<ST, EM, E, OT, FT, C, I, R>
where
    ST: StagesTuple<EM, E, OT, FT, C, I, R>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    fn stages(&self) -> &ST {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut ST {
        &mut self.stages
    }
}

impl<ST, EM, E, OT, FT, C, I, R> StdFuzzer<ST, EM, E, OT, FT, C, I, R>
where
    ST: StagesTuple<EM, E, OT, FT, C, I, R>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    pub fn new(stages: ST) -> Self {
        Self {
            stages: stages,
            phantom: PhantomData,
        }
    }
}

// TODO: no_std test
#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        executors::{Executor, ExitKind, InMemoryExecutor},
        inputs::{BytesInput, Input},
        mutators::{mutation_bitflip, ComposedByMutations, StdScheduledMutator},
        stages::StdMutationalStage,
        state::{Fuzzer, State, StdFuzzer},
        tuples::tuple_list,
        utils::StdRand,
    };

    #[cfg(feature = "std")]
    use crate::events::{LoggerEventManager, SimpleStats};

    fn harness<E: Executor<I>, I: Input>(_executor: &E, _buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_fuzzer() {
        let mut rand = StdRand::new(0);

        let mut corpus = InMemoryCorpus::<BytesInput, StdRand>::new();
        let testcase = Testcase::new(vec![0; 4]).into();
        corpus.add(testcase);

        let mut state = State::new(tuple_list!());

        let mut event_manager = LoggerEventManager::new(SimpleStats::new(|s| {
            println!("{}", s);
        }));

        let mut executor = InMemoryExecutor::new(
            "main",
            harness,
            tuple_list!(),
            //Box::new(|_, _, _, _, _| ()),
            &state,
            &corpus,
            &mut event_manager,
        );

        let mut mutator = StdScheduledMutator::new();
        mutator.add_mutation(mutation_bitflip);
        let stage = StdMutationalStage::new(mutator);
        let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

        for i in 0..1000 {
            fuzzer
                .fuzz_one(
                    &mut rand,
                    &mut executor,
                    &mut state,
                    &mut corpus,
                    &mut event_manager,
                )
                .expect(&format!("Error in iter {}", i));
        }

        let state_serialized = postcard::to_allocvec(&state).unwrap();
        let state_deserialized: State<BytesInput, StdRand, ()> =
            postcard::from_bytes(state_serialized.as_slice()).unwrap();
        assert_eq!(state.executions, state_deserialized.executions);

        let corpus_serialized = postcard::to_allocvec(&corpus).unwrap();
        let corpus_deserialized: InMemoryCorpus<BytesInput, StdRand> =
            postcard::from_bytes(corpus_serialized.as_slice()).unwrap();
        assert_eq!(corpus.count(), corpus_deserialized.count());
    }
}
