//! The queue corpus scheduler implements an AFL-like queue mechanism

use core::marker::PhantomData;

use alloc::borrow::ToOwned;

use crate::{
    corpus::Corpus, inputs::Input, prelude::State, schedulers::Scheduler, state::HasCorpus, Error,
};

/// Walk the corpus in a queue-like fashion
#[derive(Debug, Clone)]
pub struct QueueScheduler<I, S> {
    phantom: PhantomData<(I, S)>,
}

impl<I, S> Scheduler for QueueScheduler<I, S>
where
    I: Input,
    S: State<Input = I> + HasCorpus,
{
    type Input = I;

    type State = S;

    /// Gets the next entry in the queue
    fn next(&self, state: &mut Self::State) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::empty("No entries in corpus".to_owned()))
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

impl<I, S> QueueScheduler<I, S> {
    /// Creates a new `QueueScheduler`
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<I, S> Default for QueueScheduler<I, S> {
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
