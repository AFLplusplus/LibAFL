use alloc::string::{String, ToString};
use core::marker::PhantomData;

use crate::{
    corpus::{Corpus, CorpusScheduler, PowerScheduleTestData},
    inputs::Input,
    stages::PowerScheduleMetadata,
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

impl<C, I, S> Default for PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I> + HasMetadata,
    C: Corpus<I>,
    I: Input,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<C, I, S> CorpusScheduler<I, S> for PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I> + HasMetadata,
    C: Corpus<I>,
    I: Input,
{
    /// Add an entry to the corpus and return its index
    fn on_add(&self, state: &mut S, idx: usize) -> Result<(), Error> {
        let current_idx = *state.corpus().current();

        let mut depth = match current_idx {
            Some(idx) => state
                .corpus()
                .get(idx)?
                .borrow_mut()
                .metadata_mut()
                .get_mut::<PowerScheduleTestData>()
                .ok_or_else(|| Error::KeyNotFound("PowerScheduleTestData not found".to_string()))?
                .depth(),
            None => 0,
        };

        // Update depth
        depth += 1;
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .add_metadata(PowerScheduleTestData::new(depth));
        Ok(())
    }

    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::Empty(String::from("No entries in corpus")))
        } else {
            let id = match state.corpus().current() {
                Some(cur) => {
                    if *cur + 1 >= state.corpus().count() {
                        let psstats = state
                            .metadata_mut()
                            .get_mut::<PowerScheduleMetadata>()
                            .ok_or_else(|| {
                                Error::KeyNotFound("PowerScheduleMetadata not found".to_string())
                            })?;
                        psstats.set_queue_cycles(psstats.queue_cycles() + 1);
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
