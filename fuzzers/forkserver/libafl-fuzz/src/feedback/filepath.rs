use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

use libafl::{
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackFactory, StateInitializer},
};
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

/// A [`CustomFilepathToTestcaseFeedback`] takes a closure which can set the file name and path for the testcase.
/// Is never interesting (use with an OR).
/// Note: If used as part of the `Objective` chain, then it will only apply to testcases which are
/// `Objectives`, vice versa for `Feedback`.
#[derive(Serialize, Deserialize)]
pub struct CustomFilepathToTestcaseFeedback<F> {
    /// Closure that returns the filename.
    func: F,
    /// The root output directory
    out_dir: PathBuf,
}

impl<F> CustomFilepathToTestcaseFeedback<F> {
    /// Create a new [`CustomFilepathToTestcaseFeedback`].
    pub fn new(func: F, out_dir: PathBuf) -> Self {
        Self { func, out_dir }
    }
}

impl<F, T> FeedbackFactory<CustomFilepathToTestcaseFeedback<F>, T>
    for CustomFilepathToTestcaseFeedback<F>
where
    F: Clone,
{
    fn create_feedback(&self, _ctx: &T) -> CustomFilepathToTestcaseFeedback<F> {
        Self {
            func: self.func.clone(),
            out_dir: self.out_dir.clone(),
        }
    }
}

impl<F> Named for CustomFilepathToTestcaseFeedback<F> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CustomFilepathToTestcaseFeedback");
        &NAME
    }
}

impl<F, S> StateInitializer<S> for CustomFilepathToTestcaseFeedback<F> {}

impl<F, EM, I, OT, S> Feedback<EM, I, OT, S> for CustomFilepathToTestcaseFeedback<F>
where
    F: FnMut(&mut S, &mut Testcase<I>, &Path) -> Result<(), Error>,
{
    #[inline]
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(false)
    }

    #[cfg(feature = "track_hit_feedbacks")]
    #[inline]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        (self.func)(state, testcase, &self.out_dir)?;
        Ok(())
    }
}
