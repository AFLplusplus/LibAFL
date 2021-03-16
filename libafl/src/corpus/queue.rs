//! The queue corpus scheduler implements an AFL-like queue mechanism

use alloc::borrow::ToOwned;
use core::marker::PhantomData;

use crate::{
    corpus::{Corpus, CorpusScheduler},
    inputs::Input,
    state::HasCorpus,
    Error,
};

/// Walk the corpus in a queue-like fashion
pub struct QueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I>,
    C: Corpus<I>,
    I: Input,
{
    phantom: PhantomData<(C, I, S)>,
}

impl<C, I, S> CorpusScheduler<I, S> for QueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I>,
    C: Corpus<I>,
    I: Input,
{
    /// Gets the next entry in the queue
    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::Empty("No entries in corpus".to_owned()))
        } else {
            let id = match state.corpus().current() {
                Some(cur) => {
                    if *cur + 1 >= state.corpus().count() {
                        0
                    } else {
                        *cur + 1
                    }
                }
                None => 0,
            };
            *state.corpus_mut().current_mut() = Some(id);
            Ok(id)
        }
    }
}

impl<C, I, S> QueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I>,
    C: Corpus<I>,
    I: Input,
{
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<C, I, S> Default for QueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I>,
    C: Corpus<I>,
    I: Input,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {

    use std::{fs, path::PathBuf};

    use crate::{
        corpus::{Corpus, CorpusScheduler, OnDiskCorpus, QueueCorpusScheduler, Testcase},
        inputs::bytes::BytesInput,
        state::{HasCorpus, State},
        utils::StdRand,
    };

    #[test]
    fn test_queuecorpus() {
        let rand = StdRand::with_seed(4);
        let scheduler = QueueCorpusScheduler::new();

        let mut q =
            OnDiskCorpus::<BytesInput>::new(PathBuf::from("target/.test/fancy/path")).unwrap();
        let t = Testcase::with_filename(
            BytesInput::new(vec![0 as u8; 4]),
            "target/.test/fancy/path/fancyfile".into(),
        );
        q.add(t).unwrap();

        let objective_q =
            OnDiskCorpus::<BytesInput>::new(PathBuf::from("target/.test/fancy/objective/path"))
                .unwrap();

        let mut state = State::new(rand, q, (), objective_q, ());

        let next_idx = scheduler.next(&mut state).unwrap();
        let filename = state
            .corpus()
            .get(next_idx)
            .unwrap()
            .borrow()
            .filename()
            .as_ref()
            .unwrap()
            .to_owned();

        assert_eq!(filename, "target/.test/fancy/path/fancyfile");

        fs::remove_dir_all("target/.test/fancy").unwrap();
    }
}
