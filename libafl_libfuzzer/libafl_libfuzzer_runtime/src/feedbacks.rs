use alloc::rc::Rc;
use core::{cell::RefCell, fmt::Debug};

use libafl::{
    alloc,
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, MinMapFeedback},
    inputs::{BytesInput, Input},
    observers::ObserversTuple,
    state::{HasMetadata, State},
    Error,
};
use libafl_bolts::{impl_serdeany, Named};
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
    fn name(&self) -> &str {
        "libfuzzer-keep"
    }
}

impl<S> Feedback<S> for LibfuzzerKeepFeedback
where
    S: State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
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
    fn name(&self) -> &str {
        "crash-cause"
    }
}

impl LibfuzzerCrashCauseFeedback {
    fn set_filename<I: Input>(&self, prefix: &str, testcase: &mut Testcase<I>) {
        let base = if let Some(filename) = testcase.filename() {
            filename.clone()
        } else {
            let name = testcase.input().as_ref().unwrap().generate_name(0);
            name
        };
        let file_path = self.artifact_prefix.dir().join(format!(
            "{}{prefix}-{base}",
            self.artifact_prefix.filename_prefix()
        ));
        *testcase.file_path_mut() = Some(file_path);
    }
}

impl<S> Feedback<S> for LibfuzzerCrashCauseFeedback
where
    S: State<Input = BytesInput>,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        self.exit_kind = *exit_kind;
        Ok(false)
    }

    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
    {
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

pub type ShrinkMapFeedback<O, S, T> = MinMapFeedback<MappedEdgeMapObserver<O, T>, S, usize>;
