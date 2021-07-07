use core::{marker::PhantomData};

use crate::{
    corpus::{Corpus},
    inputs::Input,
    state::HasCorpus,
};

pub struct PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I>,
    C: Corpus<I>,
    I: Input,
{
    phantom: PhantomData<(C, I, S)>,
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