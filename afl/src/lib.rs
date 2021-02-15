/*!
Welcome to libAFL
*/

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate static_assertions;

pub mod bolts;
pub mod corpus;
pub mod events;
pub mod executors;
pub mod feedbacks;
pub mod generators;
pub mod inputs;
pub mod mutators;
pub mod observers;
pub mod stages;
pub mod state;
pub mod stats;
pub mod utils;

use alloc::string::String;
use core::{fmt, marker::PhantomData};
use corpus::Corpus;
use events::{Event, EventManager};
use executors::{Executor, HasObservers};
use feedbacks::FeedbacksTuple;
use inputs::Input;
use observers::ObserversTuple;
use stages::StagesTuple;
use state::{HasCorpus, State};
use utils::{current_milliseconds, current_time, Rand};

#[cfg(feature = "std")]
use std::{env::VarError, io, num::ParseIntError, string::FromUtf8Error};

/// The main fuzzer trait.
pub trait Fuzzer<C, E, EM, FT, ST, I, OC, OFT, OT, R>
where
    ST: StagesTuple<C, E, EM, FT, I, OC, OFT, OT, R>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
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
        state: &mut State<C, FT, I, OC, OFT, R>,
        manager: &mut EM,
    ) -> Result<usize, Error> {
        let (_, idx) = state.corpus_mut().next(rand)?;

        self.stages_mut()
            .perform_all(rand, executor, state, manager, idx)?;

        manager.process(state)?;
        Ok(idx)
    }

    fn fuzz_loop(
        &mut self,
        rand: &mut R,
        executor: &mut E,
        state: &mut State<C, FT, I, OC, OFT, R>,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let mut last = current_milliseconds();
        loop {
            self.fuzz_one(rand, executor, state, manager)?;
            let cur = current_milliseconds();
            if cur - last > 60 * 100 {
                last = cur;
                manager.fire(
                    state,
                    Event::UpdateStats {
                        executions: state.executions(),
                        time: current_time(),
                        phantom: PhantomData,
                    },
                )?
            }
        }
    }
}

/// Your default fuzzer instance, for everyday use.
#[derive(Clone, Debug)]
pub struct StdFuzzer<C, E, EM, FT, ST, I, OC, OFT, OT, R>
where
    ST: StagesTuple<C, E, EM, FT, I, OC, OFT, OT, R>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
    OT: ObserversTuple,
    FT: FeedbacksTuple<I>,
    C: Corpus<I, R>,
    I: Input,
    R: Rand,
{
    stages: ST,
    phantom: PhantomData<(EM, E, OC, OFT, OT, FT, C, I, R)>,
}

impl<C, E, EM, FT, ST, I, OC, OFT, OT, R> Fuzzer<C, E, EM, FT, ST, I, OC, OFT, OT, R>
    for StdFuzzer<C, E, EM, FT, ST, I, OC, OFT, OT, R>
where
    ST: StagesTuple<C, E, EM, FT, I, OC, OFT, OT, R>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
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

impl<C, E, EM, FT, ST, I, OC, OFT, OT, R> StdFuzzer<C, E, EM, FT, ST, I, OC, OFT, OT, R>
where
    ST: StagesTuple<C, E, EM, FT, I, OC, OFT, OT, R>,
    EM: EventManager<I>,
    E: Executor<I> + HasObservers<OT>,
    OC: Corpus<I, R>,
    OFT: FeedbacksTuple<I>,
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

/// Main error struct for AFL
#[derive(Debug)]
pub enum Error {
    /// Serialization error
    Serialize(String),
    /// File related error
    #[cfg(feature = "std")]
    File(io::Error),
    /// Optional val was supposed to be set, but isn't.
    EmptyOptional(String),
    /// Key not in Map
    KeyNotFound(String),
    /// No elements in the current item
    Empty(String),
    /// End of iteration
    IteratorEnd(String),
    /// This is not supported (yet)
    NotImplemented(String),
    /// You're holding it wrong
    IllegalState(String),
    /// The argument passed to this method or function is not valid
    IllegalArgument(String),
    /// Something else happened
    Unknown(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Serialize(s) => write!(f, "Error in Serialization: `{0}`", &s),
            #[cfg(feature = "std")]
            Self::File(err) => write!(f, "File IO failed: {:?}", &err),
            Self::EmptyOptional(s) => write!(f, "Optional value `{0}` was not set", &s),
            Self::KeyNotFound(s) => write!(f, "Key `{0}` not in Corpus", &s),
            Self::Empty(s) => write!(f, "No items in {0}", &s),
            Self::IteratorEnd(s) => {
                write!(f, "All elements have been processed in {0} iterator", &s)
            }
            Self::NotImplemented(s) => write!(f, "Not implemented: {0}", &s),
            Self::IllegalState(s) => write!(f, "Illegal state: {0}", &s),
            Self::IllegalArgument(s) => write!(f, "Illegal argument: {0}", &s),
            Self::Unknown(s) => write!(f, "Unknown error: {0}", &s),
        }
    }
}

/// Stringify the postcard serializer error
impl From<postcard::Error> for Error {
    fn from(err: postcard::Error) -> Self {
        Self::Serialize(format!("{:?}", err))
    }
}

/// Create an AFL Error from io Error
#[cfg(feature = "std")]
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::File(err)
    }
}

#[cfg(feature = "std")]
impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Self::Unknown(format!("Could not convert byte to utf-8: {:?}", err))
    }
}

#[cfg(feature = "std")]
impl From<VarError> for Error {
    fn from(err: VarError) -> Self {
        Self::Empty(format!("Could not get env var: {:?}", err))
    }
}

#[cfg(feature = "std")]
impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        Self::Unknown(format!("Failed to parse Int: {:?}", err))
    }
}

// TODO: no_std test
#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use crate::{
        bolts::tuples::tuple_list,
        corpus::{Corpus, InMemoryCorpus, Testcase},
        executors::{Executor, ExitKind, InProcessExecutor},
        inputs::{BytesInput, Input},
        mutators::{mutation_bitflip, ComposedByMutations, StdScheduledMutator},
        stages::StdMutationalStage,
        state::{HasCorpus, State},
        stats::SimpleStats,
        utils::StdRand,
        Fuzzer, StdFuzzer,
    };

    #[cfg(feature = "std")]
    use crate::events::LoggerEventManager;

    fn harness<E: Executor<I>, I: Input>(_executor: &E, _buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_fuzzer() {
        let mut rand = StdRand::new(0);

        let mut corpus = InMemoryCorpus::<BytesInput, StdRand>::new();
        let testcase = Testcase::new(vec![0; 4]).into();
        corpus.add(testcase);

        let mut state = State::new(
            corpus,
            tuple_list!(),
            InMemoryCorpus::<BytesInput, StdRand>::new(),
            tuple_list!(),
        );

        let stats = SimpleStats::new(|s| {
            println!("{}", s);
        });
        let mut event_manager = LoggerEventManager::new(stats);

        let mut executor = InProcessExecutor::new(
            "main",
            harness,
            tuple_list!(),
            //Box::new(|_, _, _, _, _| ()),
            &mut state,
            &mut event_manager,
        );

        let mut mutator = StdScheduledMutator::new();
        mutator.add_mutation(mutation_bitflip);
        let stage = StdMutationalStage::new(mutator);
        let mut fuzzer = StdFuzzer::new(tuple_list!(stage));

        for i in 0..1000 {
            fuzzer
                .fuzz_one(&mut rand, &mut executor, &mut state, &mut event_manager)
                .expect(&format!("Error in iter {}", i));
        }

        let state_serialized = postcard::to_allocvec(&state).unwrap();
        let state_deserialized: State<
            InMemoryCorpus<BytesInput, _>,
            (),
            BytesInput,
            InMemoryCorpus<BytesInput, _>,
            (),
            StdRand,
        > = postcard::from_bytes(state_serialized.as_slice()).unwrap();
        assert_eq!(state.executions(), state_deserialized.executions());

        let corpus_serialized = postcard::to_allocvec(state.corpus()).unwrap();
        let corpus_deserialized: InMemoryCorpus<BytesInput, StdRand> =
            postcard::from_bytes(corpus_serialized.as_slice()).unwrap();
        assert_eq!(state.corpus().count(), corpus_deserialized.count());
    }
}
