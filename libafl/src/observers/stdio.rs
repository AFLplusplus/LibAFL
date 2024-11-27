//! Observers for `stdout` and `stderr`
//!
//! The [`StdOutObserver`] and [`StdErrObserver`] observers look at the stdout of a program
//! The executor must explicitly support these observers.
#![cfg_attr(
    all(feature = "std", unix),
    doc = r"For example, they are supported on the [`crate::executors::CommandExecutor`]."
)]

use alloc::borrow::Cow;
use std::vec::Vec;

use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use crate::{observers::Observer, Error};

/// An observer that captures stdout of a target.
/// Only works for supported executors.
///
/// # Example usage
#[cfg_attr(all(feature = "std", target_os = "linux", not(miri)), doc = " ```")] // miri doesn't like the Command crate, linux as a shorthand for the availability of base64
#[cfg_attr(
    not(all(feature = "std", target_os = "linux", not(miri))),
    doc = " ```ignore"
)]
/// use std::borrow::Cow;
///
/// use libafl::{
///     corpus::{Corpus, InMemoryCorpus, Testcase},
///     events::{EventFirer, NopEventManager},
///     executors::{CommandExecutor, ExitKind},
///     feedbacks::{Feedback, StateInitializer},
///     inputs::{BytesInput, UsesInput},
///     mutators::{MutationResult, NopMutator},
///     observers::{ObserversTuple, StdErrObserver, StdOutObserver},
///     schedulers::QueueScheduler,
///     stages::StdMutationalStage,
///     state::{HasCorpus, State, StdState},
///     Error, Fuzzer, StdFuzzer,
/// };
///
/// use libafl_bolts::{
///     current_nanos,
///     rands::StdRand,
///     tuples::{tuple_list, Handle, Handled, MatchNameRef},
///     Named,
/// };
///
/// static mut STDOUT: Option<Vec<u8>> = None;
/// static mut STDERR: Option<Vec<u8>> = None;
///
/// #[derive(Clone)]
/// struct ExportStdXObserver {
///     stdout_observer: Handle<StdOutObserver>,
///     stderr_observer: Handle<StdErrObserver>,
/// }
///
/// impl<S> StateInitializer<S> for ExportStdXObserver {}
///
///
/// impl<EM, I, OT, S> Feedback<EM, I, OT, S> for ExportStdXObserver
/// where
///     S: State,
///     OT: MatchNameRef
/// {
///     fn is_interesting(
///         &mut self,
///         _state: &mut S,
///         _manager: &mut EM,
///         _input: &I,
///         observers: &OT,
///         _exit_kind: &ExitKind,
///     ) -> Result<bool, Error>
///     {
///         unsafe {
///             STDOUT = observers.get(&self.stdout_observer).unwrap().stdout.clone();
///             STDERR = observers.get(&self.stderr_observer).unwrap().stderr.clone();
///         }
///         Ok(true)
///     }
///
/// #[cfg(feature = "track_hit_feedbacks")]
///     fn last_result(&self) -> Result<bool, Error> {
///         Ok(true)
///     }
/// }
///
/// impl Named for ExportStdXObserver {
///     fn name(&self) -> &Cow<'static, str> {
///         &Cow::Borrowed("ExportStdXObserver")
///     }
/// }
///
/// fn main() {
///     let input_text = "Hello, World!";
///     let encoded_input_text = "SGVsbG8sIFdvcmxkIQo=";
///
///     let stdout_observer = StdOutObserver::new("stdout-observer");
///     let stderr_observer = StdErrObserver::new("stderr-observer");
///
///     let mut feedback = ExportStdXObserver {
///         stdout_observer: stdout_observer.handle(),
///         stderr_observer: stderr_observer.handle(),
///     };
///
///     let mut objective = ();
///
///     let mut executor = CommandExecutor::builder()
///         .program("base64")
///         .arg("--decode")
///         .stdout_observer(stdout_observer.handle())
///         .stderr_observer(stderr_observer.handle())
///         .build(tuple_list!(stdout_observer, stderr_observer))
///         .unwrap();
///
///     let mut state = StdState::new(
///         StdRand::with_seed(current_nanos()),
///         InMemoryCorpus::new(),
///         InMemoryCorpus::new(),
///         &mut feedback,
///         &mut objective,
///     )
///     .unwrap();
///
///     let scheduler = QueueScheduler::new();
///     let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
///     let mut manager = NopEventManager::new();
///
///     let mut stages = tuple_list!(StdMutationalStage::new(NopMutator::new(
///         MutationResult::Mutated
///     )));
///
///     state
///         .corpus_mut()
///         .add(Testcase::new(BytesInput::from(
///             encoded_input_text.as_bytes().to_vec(),
///         )))
///         .unwrap();
///
///     let corpus_id = fuzzer
///         .fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)
///         .unwrap();
///
///     unsafe {
///         assert!(input_text
///             .as_bytes()
///             .iter()
///             .zip(STDOUT.as_ref().unwrap().iter().filter(|e| **e != 10)) // ignore newline chars
///             .all(|(&a, &b)| a == b));
///         assert!(STDERR.as_ref().unwrap().is_empty());
///     }
///
///     state
///         .corpus()
///         .get(corpus_id)
///         .unwrap()
///         .replace(Testcase::new(BytesInput::from(
///             encoded_input_text.bytes().skip(1).collect::<Vec<u8>>(), // skip one char to make it invalid code
///         )));
///
///     fuzzer
///         .fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)
///         .unwrap();
///
///     unsafe {
///         let compare_vec: Vec<u8> = Vec::new();
///         assert_eq!(compare_vec, *STDERR.as_ref().unwrap());
///         // stdout will still contain data, we're just checking that there is an error message
///     }
/// }
/// ```

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StdOutObserver {
    /// The name of the observer.
    pub name: Cow<'static, str>,
    /// The stdout of the target during its last execution.
    pub stdout: Option<Vec<u8>>,
}

/// An observer that captures stdout of a target.
impl StdOutObserver {
    /// Create a new [`StdOutObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            stdout: None,
        }
    }

    /// React to new `stdout`
    pub fn observe_stdout(&mut self, stdout: &[u8]) {
        self.stdout = Some(stdout.into());
    }
}

impl Named for StdOutObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S> Observer<I, S> for StdOutObserver {
    fn pre_exec_child(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.stdout = None;
        Ok(())
    }

    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.stdout = None;
        Ok(())
    }
}

/// An observer that captures stderr of a target.
/// Only works for supported executors.
///
/// Check docs for [`StdOutObserver`] for example.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StdErrObserver {
    /// The name of the observer.
    pub name: Cow<'static, str>,
    /// The stderr of the target during its last execution.
    pub stderr: Option<Vec<u8>>,
}

/// An observer that captures stderr of a target.
impl StdErrObserver {
    /// Create a new [`StdErrObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            stderr: None,
        }
    }

    /// React to new `stderr`
    pub fn observe_stderr(&mut self, stderr: &[u8]) {
        self.stderr = Some(stderr.into());
    }
}

impl Named for StdErrObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S> Observer<I, S> for StdErrObserver {
    fn pre_exec_child(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.stderr = None;
        Ok(())
    }

    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.stderr = None;
        Ok(())
    }
}
