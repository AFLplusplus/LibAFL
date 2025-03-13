use alloc::rc::Rc;
use core::{cell::RefCell, fmt::Debug};
use std::borrow::Cow;

use libafl::{
    Error, HasMetadata, alloc,
    corpus::Testcase,
    executors::ExitKind,
    feedbacks::{Feedback, MinMapFeedback, StateInitializer},
    inputs::{BytesInput, Input},
    state::HasCorpus,
};
use libafl_bolts::{Named, impl_serdeany, tuples::MatchNameRef};
use libafl_targets::OomFeedback;
use serde::{Deserialize, Serialize};

use crate::{observers::MappedEdgeMapObserver, options::ArtifactPrefix};

#[derive(Debug)]
pub struct LibfuzzerKeepFeedback {
    keep: Rc<RefCell<bool>>,
}

impl LibfuzzerKeepFeedback {
    pub fn new() -> Self {
        Self {
            keep: Rc::new(RefCell::new(false)),
        }
    }

    pub fn keep(&self) -> Rc<RefCell<bool>> {
        self.keep.clone()
    }
}

impl Named for LibfuzzerKeepFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("libfuzzer-keep");
        &NAME
    }
}

impl<S> StateInitializer<S> for LibfuzzerKeepFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for LibfuzzerKeepFeedback
where
    S: HasCorpus<I>,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(*self.keep.borrow())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(*self.keep.borrow())
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct LibfuzzerCrashCauseMetadata {
    kind: ExitKind,
}

impl_serdeany!(LibfuzzerCrashCauseMetadata);

impl LibfuzzerCrashCauseMetadata {
    pub fn kind(&self) -> ExitKind {
        self.kind
    }
}

#[derive(Debug)]
pub struct LibfuzzerCrashCauseFeedback {
    artifact_prefix: ArtifactPrefix,
    exit_kind: ExitKind,
}

impl LibfuzzerCrashCauseFeedback {
    pub fn new(artifact_prefix: ArtifactPrefix) -> Self {
        Self {
            artifact_prefix,
            exit_kind: ExitKind::Ok,
        }
    }
}

impl Named for LibfuzzerCrashCauseFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("crash-cause");
        &NAME
    }
}

impl LibfuzzerCrashCauseFeedback {
    fn set_filename<I: Input>(&self, prefix: &str, testcase: &mut Testcase<I>) {
        let base = if let Some(filename) = testcase.filename() {
            filename.clone()
        } else {
            testcase.input().as_ref().unwrap().generate_name(None)
        };
        let file_path = self.artifact_prefix.dir().join(format!(
            "{}{prefix}-{base}",
            self.artifact_prefix.filename_prefix()
        ));
        *testcase.file_path_mut() = Some(file_path);
    }
}

impl<S> StateInitializer<S> for LibfuzzerCrashCauseFeedback {}

impl<EM, OT, S> Feedback<EM, BytesInput, OT, S> for LibfuzzerCrashCauseFeedback
where
    OT: MatchNameRef,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &BytesInput,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        self.exit_kind = *exit_kind;
        Ok(false)
    }
    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(false)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<BytesInput>,
    ) -> Result<(), Error> {
        match self.exit_kind {
            ExitKind::Crash | ExitKind::Oom if OomFeedback::oomed() => {
                self.set_filename("oom", testcase);
                testcase.add_metadata(LibfuzzerCrashCauseMetadata {
                    kind: ExitKind::Oom,
                });
            }
            ExitKind::Crash => {
                self.set_filename("crash", testcase);
                testcase.add_metadata(LibfuzzerCrashCauseMetadata {
                    kind: ExitKind::Crash,
                });
            }
            ExitKind::Timeout => {
                self.set_filename("timeout", testcase);
                testcase.add_metadata(LibfuzzerCrashCauseMetadata {
                    kind: ExitKind::Timeout,
                });
            }
            _ => {
                self.set_filename("uncategorized", testcase);
                testcase.add_metadata(LibfuzzerCrashCauseMetadata {
                    kind: self.exit_kind,
                });
            }
        }
        Ok(())
    }
}

pub type ShrinkMapFeedback<C, O, T> = MinMapFeedback<C, MappedEdgeMapObserver<O, T>>;
