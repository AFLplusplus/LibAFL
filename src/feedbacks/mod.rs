use crate::corpus::Testcase;
use crate::executors::Executor;
use crate::observers::MapObserver;

pub trait Feedback {
    /// is_interesting should return the "Interestingness" from 0 to 255 (percent times 2.55)
    fn is_interesting(&mut self, executor: &dyn Executor, entry: &dyn Testcase) -> u8;
}

use crate::observers::StaticMapObserver;
pub struct CovFeedback<'a> {
    virgin_bits: Vec<u8>,
    smo: &'a StaticMapObserver,
}

impl<'a> Feedback for CovFeedback<'a> {
    fn is_interesting(&mut self, _executor: &dyn Executor, _entry: &dyn Testcase) -> u8 {
        let mut interesting = 0;
        // TODO: impl. correctly, optimize
        for (virgin, map) in self.virgin_bits.iter_mut().zip(self.smo.get_map().iter()) {
            if virgin != map {
                *virgin = *map;
                if interesting < 250 {
                    interesting += 25
                }
            }
        }

        interesting
    }
}

impl<'a> CovFeedback<'a> {
    /// Create new CovFeedback using a static map observer
    pub fn new(smo: &'a StaticMapObserver) -> Self {
        CovFeedback {
            smo: smo,
            virgin_bits: vec![0; smo.get_map().len()],
        }
    }
}
