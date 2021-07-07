use core::marker::PhantomData;

use crate::{
    corpus::{Corpus, CorpusScheduler, PowerScheduleData},
    inputs::Input,
    state::{HasCorpus, HasMetadata},
    Error,
};

pub struct PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I>,
    C: Corpus<I>,
    I: Input,
{
    phantom: PhantomData<(C, I, S)>,
}

impl<C, I, S> CorpusScheduler<I, S> for PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I>,
    C: Corpus<I>,
    I: Input,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        let current_idx = state.corpus().current().unwrap();
        let parent_depth = state
            .corpus()
            .get(current_idx)?
            .borrow_mut()
            .metadata_mut()
            .get_mut::<PowerScheduleData>()
            .unwrap()
            .depth;

        // Update depth
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .metadata_mut()
            .get_mut::<PowerScheduleData>()
            .unwrap()
            .depth = parent_depth + 1;
        Ok(())
    }

    /// TODO
    /// This: https://github.com/mboehme/aflfast/blob/7819aeccfb74afad1c475ea49b92d27f536e1c51/afl-fuzz.c#L342
    fn next(&self, _state: &mut S) -> Result<usize, Error> {
        /*
        if state.corpus().count() == 0 {
            Err(Error::Empty("No entries in corpus".to_owned()))
        } else {
            let len = state.corpus().count();
            let id = state.rand_mut().below(len as u64) as usize;
            *state.corpus_mut().current_mut() = Some(id);
            Ok(id)
        }*/
        Ok(0)
    }
}

impl<C, I, S> PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I>,
    C: Corpus<I>,
    I: Input,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}
