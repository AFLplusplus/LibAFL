use core::{marker::PhantomData, time::Duration};

use crate::{
    corpus::{Corpus, CorpusScheduler},
    inputs::Input,
    state::HasCorpus,
    Error,
};


pub trait HasCalAverage{
    fn total_cal_us(&self) -> Duration;

    fn total_cal_cycles(&self) -> usize;

    fn total_bitmap_size(&self) -> usize;
}

pub struct PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I>,
    C: Corpus<I>,
    I: Input,
{
    total_cal_us: Duration,
    total_cal_cycles: usize,
    total_bitmap_size: usize,
    phantom: PhantomData<(C, I, S)>,
}

impl<C, I, S> HasCalAverage for PowerQueueCorpusScheduler<C, I, S>
where
    S: HasCorpus<C, I>,
    C: Corpus<I>,
    I: Input,
{
    fn total_cal_us(&self) -> Duration{
        self.total_cal_us
    }

    fn total_cal_cycles(&self) -> usize{
        self.total_cal_cycles
    }

    fn total_bitmap_size(&self) -> usize{
        self.total_bitmap_size
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
            total_cal_us: Duration::from_millis(0),
            total_cal_cycles: 0,
            total_bitmap_size: 0,
            phantom: PhantomData,
        }
    }
}