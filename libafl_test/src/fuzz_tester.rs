use std::marker::PhantomData;

use libafl::{
    corpus::{NopCorpus,CorpusId},
    events::{NopEventManager, ProgressReporter},
    feedbacks::ConstFeedback,
    inputs::{BytesInput, UsesInput},
    mutators::mutations::BitFlipMutator,
    schedulers::StdScheduler,
    stages::{StagesTuple, StdMutationalStage},
    executors::{HasObservers,Executor, ExitKind},
    state::{
        HasClientPerfMonitor, HasExecutions, HasLastReportTime, HasMetadata, State, StdState,
        UsesState, HasRand
    },
    generators::{Generator,RandBytesGenerator},
    Fuzzer, StdFuzzer,
    Error,
};
use libafl_bolts::rands::{RomuDuoJrRand, StdRand};

pub struct TestFuzzer<S, E, EM, F, ST>
where
    S: HasClientPerfMonitor + HasMetadata + HasExecutions + HasLastReportTime + UsesInput + State,
    E: HasObservers<State = S> + Executor<EM, F>,
    EM: ProgressReporter<State = S>,
    F: Fuzzer<E, EM, ST> + UsesState<State = S>,
    ST: StagesTuple<E, EM, S, F>
{
    state: S,
    fuzzer: F,
    manager: EM,
    _phantom: (PhantomData<E>, PhantomData<ST>),
}

//where S: HasClientPerfMonitor + HasMetadata + HasExecutions + HasLastReportTime + UsesInput + State,

pub type DefaultFuzzer = StdFuzzer<StdScheduler<DefaultState>, ConstFeedback, ConstFeedback, ()>;
pub type DefaultState =
StdState<BytesInput, NopCorpus<BytesInput>, RomuDuoJrRand, NopCorpus<BytesInput>>;
pub type DefaultEventManager = NopEventManager<DefaultState>;
pub type DefaultStage = ();


impl<S, E, EM, F, ST> TestFuzzer<S, E, EM, F, ST>
where
    S: HasClientPerfMonitor + HasMetadata + HasExecutions + HasLastReportTime + UsesInput + State,
    E: HasObservers<State = S> + Executor<EM, F>,
    EM: ProgressReporter<State = S>,
    F: Fuzzer<E, EM, ST> + UsesState<State = S>,
    ST: StagesTuple<E, EM, S, F>,
{
    pub fn new(state: S, fuzzer: F, manager: EM) -> Self {

        Self {
            state: state,
            fuzzer: fuzzer,
            manager: manager,
            _phantom: (PhantomData, PhantomData),
        }
    }

    pub fn state(&self) -> &S {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    pub fn manager(&self) -> &EM {
        &self.manager
    }

    pub fn manager_mut(&mut self) -> &mut EM {
        &mut self.manager
    }

    pub fn fuzzer(&self) -> &F {
        &self.fuzzer
    }

    pub fn fuzzer_mut(&mut self) -> &mut F {
        &mut self.fuzzer
    }

    pub fn execute_one_input(&mut self, executor: &mut E, input: &S::Input) -> Result<ExitKind, Error>{
        executor.run_target(&mut self.fuzzer, &mut self.state, &mut self.manager, input)
    }
    
    pub fn fuzz_one(&mut self, executor: &mut E , stages: &mut ST) -> Result<CorpusId, Error>{
        self.fuzzer.fuzz_one(stages, executor, &mut self.state, &mut self.manager)
    }
}

//special case for BytesInput

impl<S, E, EM, F, ST> TestFuzzer<S, E, EM, F, ST>
where
    S: HasClientPerfMonitor + HasMetadata + HasExecutions + HasLastReportTime + UsesInput<Input = BytesInput> + State + HasRand,
    E: HasObservers<State = S> + Executor<EM, F>,
    EM: ProgressReporter<State = S>,
    F: Fuzzer<E, EM, ST> + UsesState<State = S>,
    ST: StagesTuple<E, EM, S, F>,
{ 
    pub fn execute_one(&mut self, executor: &mut E) -> Result<ExitKind, Error>{
        let mut generator = RandBytesGenerator::new(1024); 

        let input = generator.generate(&mut self.state).expect("Failed to generate random bytesinput");

        self.execute_one_input(executor, &input) 
    }
}



impl<E> Default for TestFuzzer<DefaultState, E, DefaultEventManager, DefaultFuzzer, DefaultStage>
where 
    E: HasObservers<State = DefaultState> + Executor<DefaultEventManager, DefaultFuzzer>,
{
    fn default() -> Self {
        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);


        let state = StdState::new(
            StdRand::default(),
            NopCorpus::new(),
            NopCorpus::new(),
            &mut feedback,
            &mut objective
        ).expect("Failed to create state");

        let fuzzer = StdFuzzer::new(
            StdScheduler::new(),
            feedback,
            objective,
        );
        

        let manager = NopEventManager::new();
        Self::new(state, fuzzer, manager)
    }
}
