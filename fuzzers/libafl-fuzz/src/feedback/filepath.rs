use std::{
    borrow::Cow,
    fmt::{Debug, Formatter},
    marker::PhantomData,
    path::PathBuf,
};

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
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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
