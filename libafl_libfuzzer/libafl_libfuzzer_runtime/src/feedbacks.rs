use alloc::rc::Rc;
use core::{cell::RefCell, fmt::Debug};

use libafl::{
    alloc,
    bolts::tuples::Named,
    corpus::Testcase,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    impl_serdeany,
    inputs::{BytesInput, Input, UsesInput},
    observers::ObserversTuple,
    state::{HasClientPerfMonitor, HasMetadata},
    Error,
};
use libafl_targets::OOMFeedback;
use serde::{Deserialize, Serialize};

use crate::options::ArtifactPrefix;

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
    S: UsesInput + HasClientPerfMonitor,
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
    artifact_prefix: Option<ArtifactPrefix>,
    exit_kind: ExitKind,
}

impl LibfuzzerCrashCauseFeedback {
    pub fn new(artifact_prefix: Option<ArtifactPrefix>) -> Self {
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
        let filename = if let Some(artifact_prefix) = self.artifact_prefix.as_ref() {
            if let Some(filename_prefix) = artifact_prefix.filename_prefix() {
                artifact_prefix
                    .dir()
                    .join(format!("{}{}-{}", filename_prefix, prefix, base))
                    .to_str()
                    .expect("Invalid filename for testcase.")
                    .to_string()
            } else {
                artifact_prefix
                    .dir()
                    .join(format!("{}-{}", prefix, base))
                    .to_str()
                    .expect("Invalid filename for testcase.")
                    .to_string()
            }
        } else {
            format!("{}-{}", prefix, base)
        };
        testcase.set_filename(filename);
    }
}

impl<S> Feedback<S> for LibfuzzerCrashCauseFeedback
where
    S: UsesInput<Input = BytesInput> + HasClientPerfMonitor,
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

    fn append_metadata<OT>(
        &mut self,
        _state: &mut S,
        _observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
    {
        match self.exit_kind {
            ExitKind::Crash | ExitKind::Oom if OOMFeedback::oomed() => {
                self.set_filename("oom", testcase);
                testcase.metadata_mut().insert(LibfuzzerCrashCauseMetadata {
                    kind: ExitKind::Oom,
                });
            }
            ExitKind::Crash => {
                self.set_filename("crash", testcase);
                testcase.metadata_mut().insert(LibfuzzerCrashCauseMetadata {
                    kind: ExitKind::Crash,
                });
            }
            ExitKind::Timeout => {
                self.set_filename("timeout", testcase);
                testcase.metadata_mut().insert(LibfuzzerCrashCauseMetadata {
                    kind: ExitKind::Timeout,
                });
            }
            _ => {
                self.set_filename("uncategorized", testcase);
                testcase.metadata_mut().insert(LibfuzzerCrashCauseMetadata {
                    kind: self.exit_kind,
                });
            }
        }
        Ok(())
    }
}
