//! The [`DumpToDiskStage`] is a stage that dumps the corpus and the solutions to disk to e.g. allow AFL to sync

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{clone::Clone, marker::PhantomData};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};

use crate::{
    Error, HasMetadata,
    corpus::{Corpus, CorpusId, Testcase},
    inputs::Input,
    stages::{Restartable, Stage},
    state::{HasCorpus, HasRand, HasSolutions},
};

/// Metadata used to store information about disk dump indexes for names
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    expect(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct DumpToDiskMetadata {
    last_corpus: Option<CorpusId>,
    last_solution: Option<CorpusId>,
}

impl_serdeany!(DumpToDiskMetadata);

/// The [`DumpToDiskStage`] is a stage that dumps the corpus and the solutions to disk
#[derive(Debug)]
pub struct DumpToDiskStage<CB1, CB2, EM, I, S, Z> {
    solutions_dir: PathBuf,
    corpus_dir: PathBuf,
    to_bytes: CB1,
    generate_filename: CB2,
    phantom: PhantomData<(EM, I, S, Z)>,
}

impl<CB1, CB2, E, EM, I, S, P, Z> Stage<E, EM, S, Z> for DumpToDiskStage<CB1, CB2, EM, I, S, Z>
where
    CB1: FnMut(&Testcase<I>, &S) -> Vec<u8>,
    CB2: FnMut(&Testcase<I>, &CorpusId) -> P,
    S: HasCorpus<I> + HasSolutions<I> + HasRand + HasMetadata,
    P: AsRef<Path>,
{
    #[inline]
    fn perform(
        &mut self,
        _fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut S,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        self.dump_state_to_disk(state)
    }
}

impl<CB1, EM, I, S, Z> Restartable<S>
    for DumpToDiskStage<CB1, fn(&Testcase<I>, &CorpusId) -> String, EM, I, S, Z>
{
    #[inline]
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        // Not executing the target, so restart safety is not needed
        Ok(true)
    }

    #[inline]
    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        // Not executing the target, so restart safety is not needed
        Ok(())
    }
}

/// Implementation for `DumpToDiskStage` with a default `generate_filename` function.
impl<CB1, EM, I, S, Z> DumpToDiskStage<CB1, fn(&Testcase<I>, &CorpusId) -> String, EM, I, S, Z>
where
    S: HasSolutions<I> + HasRand + HasMetadata,
    I: Input,
{
    /// Create a new [`DumpToDiskStage`] with a default `generate_filename` function.
    pub fn new<A, B>(to_bytes: CB1, corpus_dir: A, solutions_dir: B) -> Result<Self, Error>
    where
        A: Into<PathBuf>,
        B: Into<PathBuf>,
    {
        Self::new_with_custom_filenames(
            to_bytes,
            Self::generate_filename, // This is now of type `fn(&Testcase<EM::Input>, &CorpusId) -> String`
            corpus_dir,
            solutions_dir,
        )
    }

    /// Default `generate_filename` function.
    #[expect(clippy::trivially_copy_pass_by_ref)]
    fn generate_filename(testcase: &Testcase<I>, id: &CorpusId) -> String {
        [
            Some(id.0.to_string()),
            testcase.filename().clone(),
            testcase
                .input()
                .as_ref()
                .map(|t| t.generate_name(Some(*id))),
        ]
        .iter()
        .flatten()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join("-")
    }
}

impl<CB1, CB2, EM, I, S, Z> DumpToDiskStage<CB1, CB2, EM, I, S, Z>
where
    S: HasMetadata + HasSolutions<I>,
{
    /// Create a new [`DumpToDiskStage`] with a custom `generate_filename` function.
    pub fn new_with_custom_filenames<A, B>(
        to_bytes: CB1,
        generate_filename: CB2,
        corpus_dir: A,
        solutions_dir: B,
    ) -> Result<Self, Error>
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
            if !solutions_dir.is_dir() {
                return Err(Error::os_error(
                    e,
                    format!("Error creating directory {solutions_dir:?}"),
                ));
            }
        }
        Ok(Self {
            to_bytes,
            generate_filename,
            solutions_dir,
            corpus_dir,
            phantom: PhantomData,
        })
    }

    #[inline]
    fn dump_state_to_disk<P: AsRef<Path>>(&mut self, state: &mut S) -> Result<(), Error>
    where
        S: HasCorpus<I>,
        CB1: FnMut(&Testcase<I>, &S) -> Vec<u8>,
        CB2: FnMut(&Testcase<I>, &CorpusId) -> P,
    {
        let (mut corpus_id, mut solutions_id) =
            if let Some(meta) = state.metadata_map().get::<DumpToDiskMetadata>() {
                (
                    meta.last_corpus.and_then(|x| state.corpus().next(x)),
                    meta.last_solution.and_then(|x| state.solutions().next(x)),
                )
            } else {
                (state.corpus().first(), state.solutions().first())
            };

        while let Some(i) = corpus_id {
            let mut testcase = state.corpus().get(i)?.borrow_mut();
            state.corpus().load_input_into(&mut testcase)?;
            let bytes = (self.to_bytes)(&testcase, state);

            let fname = self
                .corpus_dir
                .join((self.generate_filename)(&testcase, &i));
            let mut f = File::create(fname)?;
            drop(f.write_all(&bytes));

            corpus_id = state.corpus().next(i);
        }

        while let Some(i) = solutions_id {
            let mut testcase = state.solutions().get(i)?.borrow_mut();
            state.solutions().load_input_into(&mut testcase)?;
            let bytes = (self.to_bytes)(&testcase, state);

            let fname = self
                .solutions_dir
                .join((self.generate_filename)(&testcase, &i));
            let mut f = File::create(fname)?;
            drop(f.write_all(&bytes));

            solutions_id = state.solutions().next(i);
        }

        state.add_metadata(DumpToDiskMetadata {
            last_corpus: state.corpus().last(),
            last_solution: state.solutions().last(),
        });

        Ok(())
    }
}
