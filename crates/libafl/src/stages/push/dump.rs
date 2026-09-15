//! Dump to disk push stage for serializing corpus items and solutions to disk.

use alloc::{borrow::Cow, vec::Vec};
use core::fmt::Debug;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use libafl_bolts::{Error, Named};

use super::{PushStage, StageStep};
use crate::{
    common::HasMetadata,
    corpus::{Corpus, CorpusId, Testcase},
    inputs::Input,
    stages::{Restartable, dump::DumpToDiskMetadata},
    state::{HasCorpus, HasSolutions},
};

/// A stage that dumps new corpus entries and solutions to disk directories.
pub struct DumpToDiskStage<CB1, CB2> {
    name: Cow<'static, str>,
    corpus_dir: PathBuf,
    solutions_dir: PathBuf,
    to_bytes: CB1,
    generate_filename: CB2,
}

/// Backwards compatibility alias for [`DumpToDiskStage`].
pub type DumpToDiskPushStage<CB1, CB2> = DumpToDiskStage<CB1, CB2>;

impl<CB1, CB2> Debug for DumpToDiskStage<CB1, CB2> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DumpToDiskStage")
            .field("name", &self.name)
            .field("corpus_dir", &self.corpus_dir)
            .field("solutions_dir", &self.solutions_dir)
            .finish_non_exhaustive()
    }
}

impl<CB1, CB2> DumpToDiskStage<CB1, CB2> {
    /// Create a new `DumpToDiskStage`.
    pub fn new<A: Into<PathBuf>, B: Into<PathBuf>>(
        corpus_dir: A,
        solutions_dir: B,
        to_bytes: CB1,
        generate_filename: CB2,
    ) -> Result<Self, Error> {
        let c_dir = corpus_dir.into();
        let s_dir = solutions_dir.into();
        if !c_dir.exists() {
            fs::create_dir_all(&c_dir)?;
        }
        if !s_dir.exists() {
            fs::create_dir_all(&s_dir)?;
        }

        Ok(Self {
            name: Cow::Borrowed("DumpToDiskStage"),
            corpus_dir: c_dir,
            solutions_dir: s_dir,
            to_bytes,
            generate_filename,
        })
    }
}

impl<CB1, CB2> Named for DumpToDiskPushStage<CB1, CB2> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<CB1, CB2, S> Restartable<S> for DumpToDiskPushStage<CB1, CB2> {
    fn should_restart(&mut self, _state: &mut S) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<CB1, CB2, EM, I, OT, P, S> PushStage<EM, I, OT, S> for DumpToDiskPushStage<CB1, CB2>
where
    CB1: FnMut(&Testcase<I>, &S) -> Vec<u8>,
    CB2: FnMut(&Testcase<I>, &CorpusId) -> P,
    I: Input,
    P: AsRef<Path>,
    S: HasCorpus<I> + HasSolutions<I> + HasMetadata,
{
    fn init(&mut self, state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        let (last_corpus, last_solution) =
            if let Some(meta) = state.metadata_map().get::<DumpToDiskMetadata>() {
                (
                    meta.last_corpus.and_then(|x| state.corpus().next(x)),
                    meta.last_solution.and_then(|x| state.solutions().next(x)),
                )
            } else {
                (state.corpus().first(), state.solutions().first())
            };

        // Dump corpus entries
        let mut id = last_corpus;
        while let Some(i) = id {
            let testcase = state.corpus().get(i)?;
            let fname = self
                .corpus_dir
                .join((self.generate_filename)(&testcase.borrow(), &i));
            let bytes = (self.to_bytes)(&testcase.borrow(), state);
            let mut f = File::create(fname)?;
            f.write_all(&bytes)?;
            id = state.corpus().next(i);
        }

        // Dump solutions
        let mut sol_id = last_solution;
        while let Some(i) = sol_id {
            let testcase = state.solutions().get(i)?;
            let fname = self
                .solutions_dir
                .join((self.generate_filename)(&testcase.borrow(), &i));
            let bytes = (self.to_bytes)(&testcase.borrow(), state);
            let mut f = File::create(fname)?;
            f.write_all(&bytes)?;
            sol_id = state.solutions().next(i);
        }

        state.add_metadata(DumpToDiskMetadata {
            last_corpus: state.corpus().last(),
            last_solution: state.solutions().last(),
        });

        Ok(())
    }

    fn step(&mut self, _state: &mut S, _manager: &mut EM) -> Result<StageStep<I>, Error> {
        Ok(StageStep::Done)
    }

    fn deinit(&mut self, _state: &mut S, _manager: &mut EM) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
#[allow(
    clippy::type_complexity,
    clippy::match_wildcard_for_single_variants,
    clippy::duration_suboptimal_units
)]
mod tests {
    use alloc::vec;
    use std::fs;

    use libafl_bolts::rands::StdRand;

    use super::*;
    use crate::{
        corpus::{Corpus, HasCurrentCorpusId, InMemoryCorpus, Testcase},
        events::NopEventManager,
        feedbacks::ConstFeedback,
        inputs::BytesInput,
        observers::StdMapObserver,
        state::StdState,
    };

    #[test]
    fn test_dump_to_disk_push_stage() {
        let temp_dir =
            std::env::temp_dir().join(format!("libafl_test_dump_{}", std::process::id()));
        let c_dir = temp_dir.join("corpus");
        let s_dir = temp_dir.join("solutions");

        let rand = StdRand::with_seed(1234);
        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let testcase = Testcase::new(BytesInput::new(vec![1, 2, 3, 4]));
        let id = corpus.add(testcase).unwrap();

        let mut feedback = ConstFeedback::new(true);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            rand,
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();
        state.set_corpus_id(id).unwrap();

        let mut stage = DumpToDiskPushStage::new(
            &c_dir,
            &s_dir,
            |tc: &Testcase<BytesInput>, _state: &_| {
                tc.input()
                    .as_ref()
                    .map_or_else(Vec::new, |i| i.as_ref().clone())
            },
            |_tc: &Testcase<BytesInput>, id: &CorpusId| format!("input_{}", id.0),
        )
        .unwrap();
        let mut mgr = NopEventManager::new();

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::init(&mut stage, &mut state, &mut mgr).unwrap();

        let res = PushStage::<
            NopEventManager,
            BytesInput,
            (StdMapObserver<'static, u8, false>, ()),
            _,
        >::step(&mut stage, &mut state, &mut mgr)
        .unwrap();
        assert!(matches!(res, StageStep::Done));

        PushStage::<NopEventManager, BytesInput, (StdMapObserver<'static, u8, false>, ()), _>::deinit(&mut stage, &mut state, &mut mgr).unwrap();
        let _ = fs::remove_dir_all(temp_dir);
    }
}
