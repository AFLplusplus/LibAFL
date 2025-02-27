//! Observers for `stdout` and `stderr`
//!
//! The [`StdOutObserver`] and [`StdErrObserver`] observers look at the stdout of a program
//! The executor must explicitly support these observers.
#![cfg_attr(
    unix,
    doc = r"For example, they are supported on the [`crate::executors::CommandExecutor`]."
)]

use alloc::{borrow::Cow, vec::Vec};
use core::marker::PhantomData;

use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use crate::{Error, observers::Observer};

/// An observer that captures stdout of a target.
/// Only works for supported executors.
///
/// # Example usage
#[cfg_attr(all(target_os = "linux", not(miri)), doc = " ```")] // miri doesn't like the Command crate, linux as a shorthand for the availability of base64
#[cfg_attr(not(all(target_os = "linux", not(miri))), doc = " ```ignore")]
/// use std::borrow::Cow;
/// use libafl::{
///     Error, Fuzzer, StdFuzzer,
///     corpus::{Corpus, InMemoryCorpus, Testcase},
///     events::{EventFirer, NopEventManager},
///     executors::{CommandExecutor, ExitKind},
///     feedbacks::{Feedback, StateInitializer},
///     inputs::BytesInput,
///     mutators::{MutationResult, NopMutator},
///     observers::{ObserversTuple, StdErrObserver, StdOutObserver},
///     schedulers::QueueScheduler,
///     stages::StdMutationalStage, state::{HasCorpus, StdState},
/// };
/// use libafl_bolts::{
///     Named, current_nanos,
///     rands::StdRand,
///     tuples::{Handle, Handled, MatchNameRef, tuple_list},
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
/// impl<EM, I, OT, S> Feedback<EM, I, OT, S> for ExportStdXObserver
/// where
///    OT: MatchNameRef,
/// {
/// fn is_interesting(
///     &mut self,
///        _state: &mut S,    
///        _manager: &mut EM,
///        _input: &I,
///        observers: &OT,
///        _exit_kind: &ExitKind,
///    ) -> Result<bool, Error> {
///        unsafe {
///            STDOUT = observers.get(&self.stdout_observer).unwrap().output.clone();
///            STDERR = observers.get(&self.stderr_observer).unwrap().output.clone();
///        }
///        Ok(true)
///    }
///
///    #[cfg(feature = "track_hit_feedbacks")]
///    fn last_result(&self) -> Result<bool, Error> {
///        Ok(true)
///    }
///  }
///
/// impl Named for ExportStdXObserver {
///    fn name(&self) -> &Cow<'static, str> {
///        &Cow::Borrowed("ExportStdXObserver")
///    }
///  }
///
///  fn main() {
///    let input_text = "Hello, World!";
///    let encoded_input_text = "SGVsbG8sIFdvcmxkIQo=";
///
///    let stdout_observer = StdOutObserver::new("stdout-observer");
///    let stderr_observer = StdErrObserver::new("stderr-observer");
///
///    let mut feedback = ExportStdXObserver {
///        stdout_observer: stdout_observer.handle(),
///        stderr_observer: stderr_observer.handle(),
///    };
///
///    let mut objective = ();
///
///    let mut executor = CommandExecutor::builder()
///        .program("base64")
///        .arg("--decode")
///        .stdout_observer(stdout_observer.handle())
///        .stderr_observer(stderr_observer.handle())
///        .build(tuple_list!(stdout_observer, stderr_observer))
///        .unwrap();
///
///    let mut state = StdState::new(
///        StdRand::with_seed(current_nanos()),
///        InMemoryCorpus::new(),
///        InMemoryCorpus::new(),
///        &mut feedback,
///        &mut objective,
///    )
///    .unwrap();
///
///    let scheduler = QueueScheduler::new();
///    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
///    let mut manager = NopEventManager::new();
///
///    let mut stages = tuple_list!(StdMutationalStage::new(NopMutator::new(
///        MutationResult::Mutated
///    )));
///
///    state
///        .corpus_mut()
///        .add(Testcase::new(BytesInput::from(
///            encoded_input_text.as_bytes().to_vec(),
///        )))
///        .unwrap();
///
///    let corpus_id = fuzzer
///        .fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)
///        .unwrap();
///
///    unsafe {
///        assert!(
///            input_text
///                .as_bytes()
///                .iter()
///                .zip(
///                    (&*(&raw const STDOUT))
///                        .as_ref()
///                        .unwrap()
///                        .iter()
///                        .filter(|e| **e != 10)
///                ) // ignore newline chars
///                .all(|(&a, &b)| a == b)
///        );
///        assert!((&*(&raw const STDERR)).as_ref().unwrap().is_empty());
///    }
///
///    state
///        .corpus()
///        .get(corpus_id)
///        .unwrap()
///        .replace(Testcase::new(BytesInput::from(
///            encoded_input_text.bytes().skip(1).collect::<Vec<u8>>(), // skip one char to make it invalid code
///        )));
///
///    fuzzer
///        .fuzz_one(&mut stages, &mut executor, &mut state, &mut manager)
///        .unwrap();
///
///    unsafe {
///        let compare_vec: Vec<u8> = Vec::new();
///        assert_eq!(compare_vec, *(&*(&raw const STDERR)).clone().unwrap());
///        // stdout will still contain data, we're just checking that there is an error message
///    }
/// }
/// ```
///
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutputObserver<T> {
    /// The name of the observer.
    pub name: Cow<'static, str>,
    /// The captured stdout/stderr data during last execution.
    pub output: Option<Vec<u8>>,
    /// Phantom data to hold the stream type
    phantom: PhantomData<T>,
}

/// Marker traits to mark stdout for the `OutputObserver`
#[derive(Debug, Clone)]
pub struct StdOutMarker;

/// Marker traits to mark stderr for the `OutputObserver`
#[derive(Debug, Clone)]
pub struct StdErrMarker;

impl<T> OutputObserver<T> {
    /// Create a new `OutputObserver` with the given name.
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(name),
            output: None,
            phantom: PhantomData,
        }
    }

    /// React to new stream data
    pub fn observe(&mut self, data: &[u8]) {
        self.output = Some(data.into());
    }
}

impl<T> Named for OutputObserver<T> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S, T> Observer<I, S> for OutputObserver<T> {
    fn pre_exec_child(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.output = None;
        Ok(())
    }

    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.output = None;
        Ok(())
    }
}

/// An observer that captures stdout of a target.
pub type StdOutObserver = OutputObserver<StdOutMarker>;
/// An observer that captures stderr of a target.
pub type StdErrObserver = OutputObserver<StdErrMarker>;
