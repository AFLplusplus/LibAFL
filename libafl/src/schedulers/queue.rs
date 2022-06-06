//! The queue corpus scheduler implements an AFL-like queue mechanism

use alloc::borrow::ToOwned;

use crate::corpus::CorpusID;
use crate::{corpus::Corpus, inputs::Input, schedulers::Scheduler, state::HasCorpus, Error};

/// Walk the corpus in a queue-like fashion
#[derive(Debug, Clone)]
pub struct QueueScheduler;

impl<I, S> Scheduler<I, S> for QueueScheduler
where
    S: HasCorpus<I>,
    I: Input,
{
    /// Gets the next entry in the queue
    fn next(&self, state: &mut S) -> Result<CorpusID, Error> {
        let id_manager = state.corpus().id_manager();
        let first_id = id_manager.first_id().ok_or(
            Error::empty("No entries in corpus".to_owned())
        )?;
        let next_id = state
            .corpus()
            .current()
            .and_then(|cur| id_manager.find_next(cur))
            .unwrap_or(first_id);
        *state.corpus_mut().current_mut() = Some(next_id);
        Ok(next_id)
    }
}

impl QueueScheduler {
    /// Creates a new `QueueScheduler`
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for QueueScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {

    use std::{fs, path::PathBuf};

    use crate::{
        bolts::rands::StdRand,
        corpus::{Corpus, OnDiskCorpus, Testcase},
        inputs::bytes::BytesInput,
        schedulers::{QueueScheduler, Scheduler},
        state::{HasCorpus, StdState},
    };

    #[test]
    fn test_queuecorpus() {
        let rand = StdRand::with_seed(4);
        let scheduler = QueueScheduler::new();

        let mut q =
            OnDiskCorpus::<BytesInput>::new(PathBuf::from("target/.test/fancy/path")).unwrap();
        let t = Testcase::with_filename(
            BytesInput::new(vec![0_u8; 4]),
            "target/.test/fancy/path/fancyfile".into(),
        );
        q.add(t).unwrap();

        let objective_q =
            OnDiskCorpus::<BytesInput>::new(PathBuf::from("target/.test/fancy/objective/path"))
                .unwrap();

        let mut state = StdState::new(rand, q, objective_q, &mut (), &mut ()).unwrap();

        let next_idx = scheduler.next(&mut state).unwrap();
        let filename = state
            .corpus()
            .get(next_idx)
            .unwrap()
            .borrow()
            .filename()
            .as_ref()
            .unwrap()
            .clone();

        assert_eq!(filename, "target/.test/fancy/path/fancyfile");

        fs::remove_dir_all("target/.test/fancy").unwrap();
    }
}
