//! The queue corpus scheduler for power schedules.

use alloc::string::{String, ToString};

use crate::{
    corpus::{Corpus, PowerScheduleTestcaseMetaData},
    inputs::Input,
    schedulers::Scheduler,
    stages::PowerScheduleMetadata,
    state::{HasCorpus, HasMetadata},
    Error,
};

/// A corpus scheduler using power schedules
#[derive(Clone, Debug)]
pub struct PowerQueueScheduler;

impl Default for PowerQueueScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl<I, S> Scheduler<I, S> for PowerQueueScheduler
where
    S: HasCorpus<I> + HasMetadata,
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
                .get_mut::<PowerScheduleTestcaseMetaData>()
                .ok_or_else(|| Error::KeyNotFound("PowerScheduleTestData not found".to_string()))?
                .depth(),
            None => 0,
        };

        // Attach a `PowerScheduleTestData` to the queue entry.
        depth += 1;
        state
            .corpus()
            .get(idx)?
            .borrow_mut()
            .add_metadata(PowerScheduleTestcaseMetaData::new(depth));
        Ok(())
    }

    fn next(&self, state: &mut S) -> Result<usize, Error> {
        if state.corpus().count() == 0 {
            Err(Error::Empty(String::from("No entries in corpus")))
        } else {
            let id = match state.corpus().current() {
                Some(cur) => {
                    if *cur + 1 >= state.corpus().count() {
                        let psmeta = state
                            .metadata_mut()
                            .get_mut::<PowerScheduleMetadata>()
                            .ok_or_else(|| {
                                Error::KeyNotFound("PowerScheduleMetadata not found".to_string())
                            })?;
                        psmeta.set_queue_cycles(psmeta.queue_cycles() + 1);
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

impl PowerQueueScheduler {
    /// Create a new [`PowerQueueScheduler`]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}
