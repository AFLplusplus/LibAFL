use std::{borrow::Cow, marker::PhantomData};

use libafl::{
    corpus::Testcase, events::EventFirer, executors::ExitKind, feedbacks::Feedback,
    observers::ObserversTuple, state::State, Error,
};
use libafl_bolts::Named;

use crate::Opt;

/// A wrapper feedback used to determine actions for initial seeds.
/// Handles `AFL_EXIT_ON_SEED_ISSUES`, `AFL_IGNORE_SEED_ISSUES` & default afl-fuzz behavior
/// then, essentially becomes benign
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct SeedFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
{
    /// Inner [`Feedback`]
    pub inner: A,
    ignore_timeouts: bool,
    ignore_seed_issues: bool,
    exit_on_seed_issues: bool,
    phantom: PhantomData<S>,
    done_loading_seeds: bool,
}
impl<A, S> SeedFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
{
    pub fn new(inner: A, opt: &Opt) -> Self {
        Self {
            inner,
            ignore_timeouts: opt.ignore_timeouts,
            ignore_seed_issues: opt.ignore_seed_issues,
            exit_on_seed_issues: opt.exit_on_seed_issues,
            phantom: PhantomData,
            done_loading_seeds: false,
        }
    }
}

impl<A, S> Feedback<S> for SeedFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
{
    fn init_state(&mut self, state: &mut S) -> Result<(), Error> {
        self.inner.init_state(state)?;
        Ok(())
    }
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        if !self.done_loading_seeds {
            match exit_kind {
                ExitKind::Timeout => {
                    if !self.ignore_timeouts {
                        if !self.ignore_seed_issues || self.exit_on_seed_issues {
                            return Err(Error::invalid_corpus(
                                "input led to a timeout; use AFL_IGNORE_SEED_ISSUES=true",
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
    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        self.inner
            .append_metadata(state, manager, observers, testcase)?;
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
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

impl<S, A> Named for SeedFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("SeedFeedback");
        &NAME
    }
}

impl<S, A> SeedFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
{
    pub fn done_loading_seeds(&mut self) {
        self.done_loading_seeds = true;
    }
}
