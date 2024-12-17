//! The [`DumpToDiskStage`] is a stage that dumps the corpus and the solutions to disk to e.g. allow AFL to sync

use alloc::vec::Vec;
use core::{clone::Clone, marker::PhantomData};
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    string::{String, ToString},
};

use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};

use crate::{
    corpus::{Corpus, CorpusId, Testcase},
    inputs::Input,
    stages::Stage,
    state::{HasCorpus, HasRand, HasSolutions},
    Error, HasMetadata,
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
pub struct DumpToDiskStage<CB1, CB2, EM, S, Z> {
    solutions_dir: PathBuf,
    corpus_dir: PathBuf,
    to_bytes: CB1,
    generate_filename: CB2,
    phantom: PhantomData<(EM, S, Z)>,
}

impl<CB1, CB2, E, EM, S, P, Z> Stage<E, EM, S, Z> for DumpToDiskStage<CB1, CB2, EM, S, Z>
where
    CB1: FnMut(&Testcase<<S::Corpus as Corpus>::Input>, &S) -> Vec<u8>,
    CB2: FnMut(&Testcase<<S::Corpus as Corpus>::Input>, &CorpusId) -> P,
    S: HasCorpus + HasSolutions + HasRand + HasMetadata,
    S::Solutions: Corpus<Input = <S::Corpus as Corpus>::Input>,
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
impl<CB1, EM, S, Z>
    DumpToDiskStage<CB1, fn(&Testcase<<S::Corpus as Corpus>::Input>, &CorpusId) -> String, EM, S, Z>
where
    S: HasCorpus + HasSolutions + HasRand + HasMetadata,
    S::Solutions: Corpus<Input = <S::Corpus as Corpus>::Input>,
    <S::Corpus as Corpus>::Input: Input,
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
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn generate_filename(
        testcase: &Testcase<<S::Corpus as Corpus>::Input>,
        id: &CorpusId,
    ) -> String {
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

impl<CB1, CB2, EM, S, Z> DumpToDiskStage<CB1, CB2, EM, S, Z>
where
    S: HasCorpus + HasMetadata + HasSolutions,
    S::Solutions: Corpus<Input = <S::Corpus as Corpus>::Input>,
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
        CB1: FnMut(&Testcase<<S::Corpus as Corpus>::Input>, &S) -> Vec<u8>,
        CB2: FnMut(&Testcase<<S::Corpus as Corpus>::Input>, &CorpusId) -> P,
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
