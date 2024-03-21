//! The [`DumpToDiskStage`] is a stage that dumps the corpus and the solutions to disk to e.g. allow AFL to sync

use alloc::{string::String, vec::Vec};
use core::{clone::Clone, marker::PhantomData};
use std::{fs, fs::File, io::Write, path::PathBuf};

use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId},
    inputs::UsesInput,
    stages::Stage,
    state::{HasCorpus, HasMetadata, HasRand, HasSolutions, UsesState},
    Error,
};

/// Metadata used to store information about disk dump indexes for names
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct DumpToDiskMetadata {
    last_corpus: Option<CorpusId>,
    last_solution: Option<CorpusId>,
}

impl_serdeany!(DumpToDiskMetadata);

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
    CB: FnMut(&<Z::State as UsesInput>::Input, &Z::State) -> Vec<u8>,
    EM: UsesState<State = Z::State>,
    E: UsesState<State = Z::State>,
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
    ) -> Result<(), Error> {
        let (mut corpus_idx, mut solutions_idx) =
            if let Some(meta) = state.metadata_map().get::<DumpToDiskMetadata>() {
                (
                    meta.last_corpus.and_then(|x| state.corpus().next(x)),
                    meta.last_solution.and_then(|x| state.solutions().next(x)),
                )
            } else {
                (state.corpus().first(), state.solutions().first())
            };

        while let Some(i) = corpus_idx {
            let mut testcase = state.corpus().get(i)?.borrow_mut();
            state.corpus().load_input_into(&mut testcase)?;
            let bytes = (self.to_bytes)(testcase.input().as_ref().unwrap(), state);

            let fname = self.corpus_dir.join(format!(
                "id_{i}_{}",
                testcase
                    .filename()
                    .as_ref()
                    .map_or_else(|| "unnamed", String::as_str)
            ));
            let mut f = File::create(fname)?;
            drop(f.write_all(&bytes));

            corpus_idx = state.corpus().next(i);
        }

        while let Some(i) = solutions_idx {
            let mut testcase = state.solutions().get(i)?.borrow_mut();
            state.solutions().load_input_into(&mut testcase)?;
            let bytes = (self.to_bytes)(testcase.input().as_ref().unwrap(), state);

            let fname = self.solutions_dir.join(format!(
                "id_{i}_{}",
                testcase
                    .filename()
                    .as_ref()
                    .map_or_else(|| "unnamed", String::as_str)
            ));
            let mut f = File::create(fname)?;
            drop(f.write_all(&bytes));

            solutions_idx = state.solutions().next(i);
        }

        state.add_metadata(DumpToDiskMetadata {
            last_corpus: state.corpus().last(),
            last_solution: state.solutions().last(),
        });

        Ok(())
    }

    #[inline]
    fn restart_progress_should_run(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        // Not executing the target, so restart safety is not needed
        Ok(true)
    }

    #[inline]
    fn clear_restart_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        // Not executing the target, so restart safety is not needed
        Ok(())
    }
}

impl<CB, EM, Z> DumpToDiskStage<CB, EM, Z>
where
    EM: UsesState<State = Z::State>,
    Z: UsesState,
    Z::State: HasCorpus + HasSolutions + HasRand + HasMetadata,
{
    /// Create a new [`DumpToDiskStage`]
    pub fn new<A, B>(to_bytes: CB, corpus_dir: A, solutions_dir: B) -> Result<Self, Error>
    where
        A: Into<PathBuf>,
        B: Into<PathBuf>,
    {
        let corpus_dir = corpus_dir.into();
        if let Err(e) = fs::create_dir(&corpus_dir) {
            if !corpus_dir.is_dir() {
                return Err(Error::os_error(
                    e,
                    format!("Error creating directory {corpus_dir:?}"),
                ));
            }
        }
        let solutions_dir = solutions_dir.into();
        if let Err(e) = fs::create_dir(&solutions_dir) {
            if !corpus_dir.is_dir() {
                return Err(Error::os_error(
                    e,
                    format!("Error creating directory {solutions_dir:?}"),
                ));
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
