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

use crate::{Error, corpus::{Corpus, CorpusId, IsTestcaseMetadataCell, Testcase, TestcaseMetadata}, inputs::Input, stages::{Restartable, Stage}, state::{HasCorpus, HasRand, HasSolutions}, HasMetadata};

/// Metadata used to store information about disk dump indexes for names
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    expect(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
#[derive(Default, Serialize, Deserialize, Debug, Clone)]
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
    CB1: FnMut(&I, &TestcaseMetadata, &S) -> Vec<u8>,
    CB2: FnMut(&I, &TestcaseMetadata, &CorpusId) -> P,
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
    for DumpToDiskStage<
        CB1,
        fn(&Testcase<I, <S::Corpus as Corpus<I>>::TestcaseMetadataCell>, &CorpusId) -> String,
        EM,
        I,
        S,
        Z,
    >
where
    S: HasCorpus<I>,
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
impl<CB1, EM, I, S, Z>
    DumpToDiskStage<
        CB1,
        fn(&Testcase<I, <S::Corpus as Corpus<I>>::TestcaseMetadataCell>, &CorpusId) -> String,
        EM,
        I,
        S,
        Z,
    >
where
    S: HasCorpus<I> + HasSolutions<I> + HasRand + HasMetadata,
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
    fn generate_filename(
        testcase: &Testcase<I, <S::Corpus as Corpus<I>>::TestcaseMetadataCell>,
        id: &CorpusId,
    ) -> String {
        // TODO: check that
        [
            Some(id.0.to_string()),
            Some(testcase.id().clone()),
            // testcase
            //     .input()
            //     .as_ref()
            //     .map(|t| t.generate_name(Some(*id))),
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
                    format!("Error creating directory {}", corpus_dir.display()),
                ));
            }
        }
        let solutions_dir = solutions_dir.into();
        if let Err(e) = fs::create_dir(&solutions_dir) {
            if !solutions_dir.is_dir() {
                return Err(Error::os_error(
                    e,
                    format!("Error creating directory {}", solutions_dir.display()),
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
        CB1: FnMut(&I, &TestcaseMetadata, &S) -> Vec<u8>,
        CB2: FnMut(&I, &TestcaseMetadata, &CorpusId) -> P,
        S: HasCorpus<I>,
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
            let testcase = state.corpus().get(i)?;

            let input = testcase.input();
            let md = testcase.testcase_metadata();

            let bytes = (self.to_bytes)(input.as_ref(), &md, state);

            let fname = self
                .corpus_dir
                .join((self.generate_filename)(input.as_ref(), &md, &i));
            let mut f = File::create(fname)?;
            drop(f.write_all(&bytes));

            corpus_id = state.corpus().next(i);
        }

        while let Some(i) = solutions_id {
            let testcase = state.solutions().get(i)?;

            let input = testcase.input();
            let md = testcase.testcase_metadata();

            let bytes = (self.to_bytes)(input.as_ref(), &md, state);

            let fname = self
                .solutions_dir
                .join((self.generate_filename)(input.as_ref(), &md, &i));
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
