use alloc::{borrow::Cow, string::String};
use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use crate::{
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackFactory},
    inputs::Input,
    observers::ObserversTuple,
    state::State,
    Error,
};

/// A [`CustomFilenameToTestcaseFeedback`] takes a closure which returns a filename for the testcase.
/// Is never interesting (use with an Eager OR).
/// Note: Use only in conjunction with a `Corpus` type that writes to disk.
/// Note: If used as part of the `Objective` chain, then it will only apply to testcases which are
/// `Objectives`, vice versa for `Feedback`.
#[derive(Serialize, Deserialize)]
pub struct CustomFilenameToTestcaseFeedback<F, I, S>
where
    I: Input,
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<I>) -> Result<String, Error>,
{
    /// Closure that returns the filename.
    func: F,
    phantomm: PhantomData<(I, S)>,
}

impl<F, I, S> CustomFilenameToTestcaseFeedback<F, I, S>
where
    I: Input,
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<I>) -> Result<String, Error>,
{
    /// Create a new [`CustomFilenameToTestcaseFeedback`].
    pub fn new(func: F) -> Self {
        Self {
            func,
            phantomm: PhantomData,
        }
    }
}

impl<F, I, S, T> FeedbackFactory<CustomFilenameToTestcaseFeedback<F, I, S>, T>
    for CustomFilenameToTestcaseFeedback<F, I, S>
where
    I: Input,
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<I>) -> Result<String, Error> + Clone,
{
    fn create_feedback(&self, _ctx: &T) -> CustomFilenameToTestcaseFeedback<F, I, S> {
        Self {
            func: self.func.clone(),
            phantomm: self.phantomm,
        }
    }
}

impl<F, I, S> Named for CustomFilenameToTestcaseFeedback<F, I, S>
where
    I: Input,
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<I>) -> Result<String, Error>,
{
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CustomFilenameToTestcaseFeedback");
        &NAME
    }
}

impl<F, I, S> Debug for CustomFilenameToTestcaseFeedback<F, I, S>
where
    I: Input,
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<I>) -> Result<String, Error>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomFilenameToTestcaseFeedback")
            .finish_non_exhaustive()
    }
}

impl<F, I, S> Feedback<S> for CustomFilenameToTestcaseFeedback<F, I, S>
where
    S: State<Input = I>,
    F: FnMut(&mut S, &mut Testcase<S::Input>) -> Result<String, Error>,
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
        *testcase.filename_mut() = Some((self.func)(state, testcase)?);
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    #[inline]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}
