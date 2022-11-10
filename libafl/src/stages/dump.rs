//! The [`DumpToDiskStage`] is a stage that dumps the corpus and the solutions to disk to e.g. allow AFL to sync

use core::{clone::Clone, marker::PhantomData};
use alloc::vec::Vec;
use std::{fs, fs::File, io::Write, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    corpus::Corpus,
    inputs::UsesInput,
    stages::Stage,
    state::{HasCorpus, HasMetadata, HasRand, HasSolutions, UsesState},
    Error,
};

/// Metadata used to store information about disk dump indexes for names
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct DumpToDiskMetadata {
    last_corpus: usize,
    last_solution: usize,
}

crate::impl_serdeany!(DumpToDiskMetadata);

/// The [`DumpToDiskStage`] is a stage that dumps the corpus and the solutions to disk
#[derive(Debug)]
pub struct DumpToDiskStage<CB, EM, Z> {
    solutions_dir: PathBuf,
    corpus_dir: PathBuf,
    to_bytes: CB,
    phantom: PhantomData<(EM, Z)>,
}

impl<CB, EM, Z> UsesState for DumpToDiskStage<CB, EM, Z>
where
    EM: UsesState,
{
    type State = EM::State;
}

impl<CB, E, EM, Z> Stage<E, EM, Z> for DumpToDiskStage<CB, EM, Z>
where
    CB: FnMut(&<Z::State as UsesInput>::Input) -> Vec<u8>,
    EM: UsesState<State = Z::State>,
    E: UsesState<State = Z::State>,
    //T: Vec<Entry = u8>,
    Z: UsesState,
    Z::State: HasCorpus + HasSolutions + HasRand + HasMetadata,
{
    #[inline]
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut Z::State,
        _manager: &mut EM,
        _corpus_idx: usize,
    ) -> Result<(), Error> {
        let meta = state
            .metadata()
            .get::<DumpToDiskMetadata>()
            .map_or_else(DumpToDiskMetadata::default, Clone::clone);

        let corpus_count = state.corpus().count();
        let solutions_count = state.solutions().count();

        for i in meta.last_corpus..corpus_count {
            let mut testcase = state.corpus().get(i)?.borrow_mut();
            let input = testcase.load_input()?;
            let bytes = (self.to_bytes)(input);

            let fname = self.corpus_dir.join(format!("id_{i}"));
            let mut f = File::create(fname)?;
            drop(f.write_all(bytes.as_slice()));
        }

        for i in meta.last_solution..solutions_count {
            let mut testcase = state.solutions().get(i)?.borrow_mut();
            let input = testcase.load_input()?;
            let bytes = (self.to_bytes)(input);

            let fname = self.solutions_dir.join(format!("id_{i}"));
            let mut f = File::create(fname)?;
            drop(f.write_all(bytes.as_slice()));
        }

        state.add_metadata(DumpToDiskMetadata {
            last_corpus: corpus_count,
            last_solution: solutions_count,
        });

        Ok(())
    }
}

impl<CB, EM, Z> DumpToDiskStage<CB, EM, Z>
where
    CB: FnMut(&<Z::State as UsesInput>::Input) -> Vec<u8>,
    EM: UsesState<State = Z::State>,
    Z: UsesState,
    Z::State: HasCorpus + HasSolutions + HasRand + HasMetadata,
{
    /// Create a new [`DumpToDiskStage`]
    #[must_use]
    pub fn new<A, B>(to_bytes: CB, corpus_dir: A, solutions_dir: B) -> Result<Self, Error>
    where
        A: Into<PathBuf>,
        B: Into<PathBuf>,
    {
        let corpus_dir = corpus_dir.into();
        if let Err(e) = fs::create_dir(&corpus_dir) {
            if !corpus_dir.is_dir() {
                return Err(Error::file(e));
            }
        }
        let solutions_dir = solutions_dir.into();
        if let Err(e) = fs::create_dir(&solutions_dir) {
            if !corpus_dir.is_dir() {
                return Err(Error::file(e));
            }
        }
        Ok(Self {
            to_bytes,
            solutions_dir,
            corpus_dir,
            phantom: PhantomData,
        })
    }
}
