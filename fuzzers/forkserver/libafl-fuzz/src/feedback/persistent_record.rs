use std::{borrow::Cow, collections::VecDeque};

use libafl::{
    corpus::{Corpus, Testcase},
    executors::ExitKind,
    feedbacks::{Feedback, FeedbackFactory, StateInitializer},
    inputs::Input,
    state::HasCorpus,
};
use libafl_bolts::{Error, Named};
use serde::{Deserialize, Serialize};

/// A [`PersitentRecordFeedback`] tracks the last N inputs that the fuzzer has run.
/// TODO: Kept in memory for now but should write to disk.
#[derive(Serialize, Deserialize)]
pub struct PersitentRecordFeedback<I> {
    /// Vec that tracks the last `record_size` [`Input`]
    record: VecDeque<I>,
    record_size: usize,
}

impl<I> PersitentRecordFeedback<I> {
    /// Create a new [`PersitentRecordFeedback`].
    pub fn new(record_size: usize) -> Self {
        Self {
            record_size,
            record: VecDeque::default(),
        }
    }
}

impl<I, T> FeedbackFactory<PersitentRecordFeedback<I>, T> for PersitentRecordFeedback<I>
where
    I: Clone,
{
    fn create_feedback(&self, _ctx: &T) -> PersitentRecordFeedback<I> {
        Self {
            record_size: self.record_size,
            record: self.record.clone(),
        }
    }
}

impl<I> Named for PersitentRecordFeedback<I> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("PersitentRecordFeedback");
        &NAME
    }
}

impl<I, S> StateInitializer<S> for PersitentRecordFeedback<I> {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for PersitentRecordFeedback<I>
where
    S: HasCorpus,
    S::Corpus: Corpus<Input = I>,
    I: Input,
{
    #[allow(clippy::wrong_self_convention)]
    #[inline]
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        if self.should_run() {
            self.record.push_back(input.clone());
            if self.record.len() == self.record_size {
                drop(self.record.pop_front());
            }
        }
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
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

impl<I> PersitentRecordFeedback<I> {
    fn should_run(&self) -> bool {
        self.record_size > 0
    }
}
