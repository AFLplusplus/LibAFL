use alloc::string::String;
use core::marker::PhantomData;

use crate::{
    corpus::{Corpus, CorpusScheduler, PowerScheduleTestData},
    inputs::Input,
    stages::PowerScheduleGlobalData,
    state::{HasCorpus, HasMetadata},
    Error,
};

pub struct PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I> + HasMetadata,
    C: Corpus<I>,
    I: Input,
{
    phantom: PhantomData<(C, I, S)>,
}

impl<C, I, S> CorpusScheduler<I, S> for PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I> + HasMetadata,
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
            .get_mut::<PowerScheduleTestData>()
            .unwrap()
            .depth;

        // Update depth
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .add_metadata(PowerScheduleTestData::new(parent_depth + 1 as u64));
        Ok(())
    }

    /// TODO
    /// This: https://github.com/mboehme/aflfast/blob/7819aeccfb74afad1c475ea49b92d27f536e1c51/afl-fuzz.c#L342
    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::Empty("No entries in corpus".to_string()))
        } else {
            let id = match state.corpus().current() {
                Some(cur) => {
                    if *cur + 1 >= state.corpus().count() {
                        0
                    } else {
                        *cur + 1
                    }
                }
                None => {
                    state
                        .metadata_mut()
                        .get_mut::<PowerScheduleGlobalData>()
                        .unwrap()
                        .queue_cycles += 1;
                    0
                }
            };
            *state.corpus_mut().current_mut() = Some(id);
            Ok(id)
        }
    }
}

impl<C, I, S> PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I> + HasMetadata,
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
