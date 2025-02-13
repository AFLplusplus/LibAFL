use std::{borrow::Cow, marker::PhantomData};

use libafl::{
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    Error,
};
use libafl_bolts::Named;

use crate::Opt;

/// A wrapper feedback used to determine actions for initial seeds.
/// Handles `AFL_EXIT_ON_SEED_ISSUES`, `AFL_IGNORE_SEED_ISSUES` & default afl-fuzz behavior
/// then, essentially becomes benign
#[expect(clippy::module_name_repetitions, clippy::struct_excessive_bools)]
#[derive(Debug)]
pub struct SeedFeedback<A, S> {
    /// Inner [`Feedback`]
    pub inner: A,
    ignore_timeouts: bool,
    ignore_seed_issues: bool,
    exit_on_seed_issues: bool,
    done_loading_seeds: bool,
    phantom: PhantomData<S>,
}
impl<A, S> SeedFeedback<A, S> {
    pub fn new(inner: A, opt: &Opt) -> Self {
        Self {
            inner,
            ignore_timeouts: opt.ignore_timeouts,
            ignore_seed_issues: opt.ignore_seed_issues,
            exit_on_seed_issues: opt.exit_on_seed_issues,
            done_loading_seeds: false,
            phantom: PhantomData,
        }
    }
}

impl<A, S> StateInitializer<S> for SeedFeedback<A, S>
where
    A: StateInitializer<S>,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.inner.init_state(state)?;
        Ok(())
    }
}

impl<A, EM, I, OT, S> Feedback<EM, I, OT, S> for SeedFeedback<A, S>
where
    A: Feedback<EM, I, OT, S>,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        if !self.done_loading_seeds {
            match exit_kind {
                ExitKind::Timeout => {
                    if !self.ignore_timeouts {
                        if !self.ignore_seed_issues || self.exit_on_seed_issues {
                            return Err(Error::invalid_corpus(
                                "input led to a timeout; use AFL_IGNORE_SEED_ISSUES=1",
                            ));
                        }
                        return Ok(false);
                    }
                }
                ExitKind::Crash => {
                    if self.exit_on_seed_issues {
                        return Err(Error::invalid_corpus("input let to a crash; either omit AFL_EXIT_ON_SEED_ISSUES or set it to false."));
                    }
                    // We regard all crashes as uninteresting during seed loading
                    return Ok(false);
                }
                _ => {}
            }
        }
        let is_interesting = self
            .inner
            .is_interesting(state, manager, input, observers, exit_kind)?;
        Ok(is_interesting)
    }
    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        self.inner
            .append_metadata(state, manager, observers, testcase)?;
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.inner.discard_metadata(state, input)?;
        Ok(())
    }
    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        self.inner.last_result()
    }
    #[cfg(feature = "track_hit_feedbacks")]
    fn append_hit_feedbacks(&self, list: &mut Vec<Cow<'static, str>>) -> Result<(), Error> {
        if self.inner.last_result()? {
            self.inner.append_hit_feedbacks(list)?;
        }
        Ok(())
    }
}

impl<A, S> Named for SeedFeedback<A, S> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("SeedFeedback");
        &NAME
    }
}

impl<A, S> SeedFeedback<A, S> {
    pub fn done_loading_seeds(&mut self) {
        self.done_loading_seeds = true;
    }
}
