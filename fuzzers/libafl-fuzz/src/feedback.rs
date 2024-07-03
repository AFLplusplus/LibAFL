use libafl::{
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackFactory},
    inputs::Input,
    observers::ObserversTuple,
    state::State,
};
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, marker::PhantomData, path::PathBuf};

use crate::Opt;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum FeedbackLocation {
    Objective,
    Feedback,
}

/// A wrapper feedback used to determine actions for initial seeds.
/// Handles `AFL_EXIT_ON_SEED_ISSUES`, `AFL_IGNORE_SEED_ISSUES` & default afl-fuzz behavior
/// then, essentially becomes a "const" feedback.
///
/// Note:
/// For `LibAFL` breaking changes, this Feedback will only work if `LibAFL` checks
/// that the Input is a `Solution` before it checks if it is `corpus_worthy`
///
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct SeedFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
{
    /// Inner [`Feedback`]
    pub inner: A,
    /// either Objective or Feedback
    location: FeedbackLocation,
    opt: Opt,
    phantom: PhantomData<S>,
    done_loading_seeds: bool,
}
impl<A, S> SeedFeedback<A, S>
where
    A: Feedback<S>,
    S: State,
{
    /// Create a new combined feedback
    pub fn new(inner: A, location: FeedbackLocation, opt: Opt) -> Self {
        Self {
            inner,
            location,
            opt,
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
        // TODO: refactor
        if !self.done_loading_seeds {
            match exit_kind {
                ExitKind::Timeout => {
                    if !self.opt.ignore_timeouts {
                        match self.location {
                            FeedbackLocation::Feedback => {
                                // We regard all timeouts as uninteresting.
                                return Ok(false);
                            }
                            FeedbackLocation::Objective => {
                                if !self.opt.ignore_seed_issues || self.opt.exit_on_seed_issues {
                                    return Err(Error::invalid_corpus(
                                        "input led to a timeout; use AFL_IGNORE_SEED_ISSUES=true",
                                    ));
                                }
                            }
                        }
                    }
                }
                ExitKind::Crash => {
                    match self.location {
                        FeedbackLocation::Feedback => {
                            // We regard all crashes as uninteresting.
                            return Ok(false);
                        }
                        FeedbackLocation::Objective => {
                            if self.opt.exit_on_seed_issues {
                                return Err(Error::invalid_corpus("input let to a crash; either omit AFL_EXIT_ON_SEED_ISSUES or set it to false."));
                            }
                            // We regard all crashes as uninteresting during seed loading
                            return Ok(false);
                        }
                    }
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
        static NAME: Cow<'static, str> = Cow::Borrowed("SeedFeedback {self.location}");
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

use std::fmt::{self, Debug, Formatter};

/// A [`CustomFilepathToTestcaseFeedback`] takes a closure which can set the file name and path for the testcase.
/// Is never interesting (use with an OR).
/// Note: If used as part of the `Objective` chain, then it will only apply to testcases which are
/// `Objectives`, vice versa for `Feedback`.
#[derive(Serialize, Deserialize)]
pub struct CustomFilepathToTestcaseFeedback<F, I, S>
where
    I: Input,
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<I>, &PathBuf) -> Result<(), Error>,
{
    /// Closure that returns the filename.
    func: F,
    /// The root output directory
    out_dir: PathBuf,
    phantomm: PhantomData<(I, S)>,
}

impl<F, I, S> CustomFilepathToTestcaseFeedback<F, I, S>
where
    I: Input,
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<I>, &PathBuf) -> Result<(), Error>,
{
    /// Create a new [`CustomFilepathToTestcaseFeedback`].
    pub fn new(func: F, out_dir: PathBuf) -> Self {
        Self {
            func,
            out_dir,
            phantomm: PhantomData,
        }
    }
}

impl<F, I, S, T> FeedbackFactory<CustomFilepathToTestcaseFeedback<F, I, S>, T>
    for CustomFilepathToTestcaseFeedback<F, I, S>
where
    I: Input,
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<I>, &PathBuf) -> Result<(), Error> + Clone,
{
    fn create_feedback(&self, _ctx: &T) -> CustomFilepathToTestcaseFeedback<F, I, S> {
        Self {
            func: self.func.clone(),
            phantomm: self.phantomm,
            out_dir: self.out_dir.clone(),
        }
    }
}

impl<F, I, S> Named for CustomFilepathToTestcaseFeedback<F, I, S>
where
    I: Input,
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<I>, &PathBuf) -> Result<(), Error>,
{
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CustomFilepathToTestcaseFeedback");
        &NAME
    }
}

impl<F, I, S> Debug for CustomFilepathToTestcaseFeedback<F, I, S>
where
    I: Input,
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<I>, &PathBuf) -> Result<(), Error>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomFilepathToTestcaseFeedback")
            .finish_non_exhaustive()
    }
}

impl<F, I, S> Feedback<S> for CustomFilepathToTestcaseFeedback<F, I, S>
where
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<S::Input>, &PathBuf) -> Result<(), Error>,
    I: Input,
{
    #[allow(clippy::wrong_self_convention)]
    #[inline]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
    {
        Ok(false)
    }

    fn append_metadata<EM, OT>(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<<S>::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        (self.func)(state, testcase, &self.out_dir)?;
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    #[inline]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}
