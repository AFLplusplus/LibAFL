//! The queue corpus implements an afl-like queue mechanism

use alloc::borrow::ToOwned;
use core::marker::PhantomData;

use crate::{
    corpus::{Corpus, CorpusScheduler},
    inputs::Input,
    state::HasCorpus,
    Error,
};

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
    /// Gets the next entry at random
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

/*
#[cfg(test)]
#[cfg(feature = "std")]
mod tests {

    use std::path::PathBuf;

    use crate::{
        corpus::{Corpus, OnDiskCorpus, QueueCorpus, Testcase},
        inputs::bytes::BytesInput,
        utils::StdRand,
    };

    #[test]
    fn test_queuecorpus() {
        let mut rand = StdRand::new(0);
        let mut q = QueueCorpus::new(OnDiskCorpus::<BytesInput, StdRand>::new(PathBuf::from(
            "fancy/path",
        )));
        let t = Testcase::with_filename(BytesInput::new(vec![0 as u8; 4]), "fancyfile".into());
        q.add(t);
        let filename = q
            .next(&mut rand)
            .unwrap()
            .0
            .borrow()
            .filename()
            .as_ref()
            .unwrap()
            .to_owned();
        assert_eq!(
            filename,
            q.next(&mut rand)
                .unwrap()
                .0
                .borrow()
                .filename()
                .as_ref()
                .unwrap()
                .to_owned()
        );
        assert_eq!(filename, "fancyfile");
    }
}
*/
