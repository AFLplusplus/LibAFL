use std::{
    borrow::Cow,
    collections::VecDeque,
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use libafl::{
    corpus::{Corpus, Testcase},
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackFactory},
    inputs::Input,
    observers::ObserversTuple,
    state::{HasCorpus, State},
};
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

/// A [`PersitentRecordFeedback`] tracks the last N inputs that the fuzzer has run.
/// TODO: Kept in memory for now but should write to disk.
#[derive(Serialize, Deserialize)]
pub struct PersitentRecordFeedback<I, S>
where
    S: State<Input = I>,
{
    /// Vec that tracks the last `record_size` [`Input`]
    record: VecDeque<I>,
    record_size: usize,
    phantomm: PhantomData<(I, S)>,
}

impl<I, S> PersitentRecordFeedback<I, S>
where
    I: Input,
    S: State<Input = I>,
{
    /// Create a new [`PersitentRecordFeedback`].
    pub fn new(record_size: usize) -> Self {
        Self {
            record_size,
            record: VecDeque::default(),
            phantomm: PhantomData,
        }
    }
}

impl<I, S, T> FeedbackFactory<PersitentRecordFeedback<I, S>, T> for PersitentRecordFeedback<I, S>
where
    I: Input,
    S: State<Input = I>,
{
    fn create_feedback(&self, _ctx: &T) -> PersitentRecordFeedback<I, S> {
        Self {
            record_size: self.record_size,
            record: self.record.clone(),
            phantomm: self.phantomm,
        }
    }
}

impl<I, S> Named for PersitentRecordFeedback<I, S>
where
    I: Input,
    S: State<Input = I>,
{
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("PersitentRecordFeedback");
        &NAME
    }
}

impl<I, S> Debug for PersitentRecordFeedback<I, S>
where
    I: Input,
    S: State<Input = I>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersitentRecordFeedback")
            .finish_non_exhaustive()
    }
}

impl<I, S> Feedback<S> for PersitentRecordFeedback<I, S>
where
    S: State<Input = I> + HasCorpus,
    I: Input,
{
    #[allow(clippy::wrong_self_convention)]
    #[inline]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
    {
        if self.should_run() {
            self.record.push_back(input.clone());
            if self.record.len() == self.record_size {
                self.record.pop_front();
            }
        }
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
        if self.should_run() {
            let file_path = testcase
                .file_path()
                .as_ref()
                .expect("file path for the testcase must be set!");
            let file_dir = file_path
                .parent()
                .expect("testcase must have a parent directory!");
            // fetch the ID for this testcase
            let id = state.corpus().peek_free_id().0;
            let record = format!("RECORD:{id:0>6}");
            // save all inputs in our persistent record
            for (i, input) in self.record.iter().enumerate() {
                let filename = file_dir.join(format!("{record},cnt{i:0>6}"));
                input.to_file(file_dir.join(filename))?;
            }
            // rewrite this current testcase's filepath
            let filename = format!("RECORD:{id:0>6},cnt:{0:0>6}", self.record.len());
            *testcase.file_path_mut() = Some(file_dir.join(&filename));
            *testcase.filename_mut() = Some(filename);
        }
        Ok(())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    #[inline]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }
}

impl<I, S> PersitentRecordFeedback<I, S>
where
    I: Input,
    S: State<Input = I>,
{
    fn should_run(&self) -> bool {
        self.record_size > 0
    }
}
