//! Executors take input, and run it in the target.

use alloc::boxed::Box;
use core::fmt::Debug;

pub use combined::CombinedExecutor;
#[cfg(all(feature = "std", any(unix, doc)))]
pub use command::CommandExecutor;
pub use differential::DiffExecutor;
#[cfg(all(feature = "std", feature = "fork", unix))]
pub use forkserver::{Forkserver, ForkserverExecutor};
pub use inprocess::InProcessExecutor;
#[cfg(all(feature = "std", feature = "fork", unix))]
pub use inprocess_fork::InProcessForkExecutor;
#[cfg(unix)]
use libafl_bolts::os::unix_signals::Signal;
use libafl_bolts::tuples::RefIndexable;
use serde::{Deserialize, Serialize};
pub use shadow::ShadowExecutor;
pub use with_observers::WithObservers;

use crate::Error;

pub mod combined;
#[cfg(all(feature = "std", any(unix, doc)))]
pub mod command;
pub mod differential;
#[cfg(all(feature = "std", feature = "fork", unix))]
pub mod forkserver;
pub mod inprocess;

/// The module for inproc fork executor
#[cfg(all(feature = "std", unix))]
pub mod inprocess_fork;

pub mod shadow;

pub mod with_observers;

/// The module for all the hooks
pub mod hooks;

/// How an execution finished.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::unsafe_derive_deserialize)] // for SerdeAny
pub enum ExitKind {
    /// The run exited normally.
    Ok,
    /// The run resulted in a target crash.
    Crash,
    /// The run hit an out of memory error.
    Oom,
    /// The run timed out
    Timeout,
    /// Special case for [`DiffExecutor`] when both exitkinds don't match
    Diff {
        /// The exitkind of the primary executor
        primary: DiffExitKind,
        /// The exitkind of the secondary executor
        secondary: DiffExitKind,
    },
    // The run resulted in a custom `ExitKind`.
    // Custom(Box<dyn SerdeAny>),
}

/// The type of the crash observed in one of the differential executors
pub type DiffExitKind = Box<ExitKind>;

libafl_bolts::impl_serdeany!(ExitKind);

/// Holds a tuple of Observers
pub trait HasObservers {
    type Observers;

    /// Get the linked observers
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers>;

    /// Get the linked observers (mutable)
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers>;
}

/// An executor takes the given inputs, and runs the harness/target.
pub trait Executor<EM, I, S, Z> {
    /// Instruct the target about the input and run
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error>;

    /// Wraps this Executor with the given [`ObserversTuple`] to implement [`HasObservers`].
    ///
    /// If the executor already implements [`HasObservers`], then the original implementation will be overshadowed by
    /// the implementation of this wrapper.
    fn with_observers<OT>(self, observers: OT) -> WithObservers<Self, OT> {
        WithObservers::new(self, observers)
    }
}

/// The common signals we want to handle
#[cfg(unix)]
#[inline]
#[must_use]
pub fn common_signals() -> &'static [Signal] {
    static SIGNALS: &'static [Signal] = &[
        Signal::SigAlarm,
        Signal::SigUser2,
        Signal::SigAbort,
        Signal::SigBus,
        #[cfg(feature = "handle_sigpipe")]
        Signal::SigPipe,
        Signal::SigFloatingPointException,
        Signal::SigIllegalInstruction,
        Signal::SigSegmentationFault,
        Signal::SigTrap,
    ];
    SIGNALS
}

#[cfg(test)]
pub mod test {
    use libafl_bolts::{AsSlice, Error};

    use crate::{
        events::NopEventManager,
        executors::{Executor, ExitKind},
        fuzzer::test::NopFuzzer,
        inputs::{BytesInput, HasTargetBytes},
        state::{HasExecutions, NopState},
    };

    /// A simple executor that does nothing.
    /// If input len is 0, `run_target` will return Err
    #[derive(Debug, Default)]
    pub struct NopExecutor;

    impl<EM, I, S, Z> Executor<EM, I, S, Z> for NopExecutor
    where
        I: HasTargetBytes,
        S: HasExecutions,
    {
        fn run_target(
            &mut self,
            _fuzzer: &mut Z,
            state: &mut Self::State,
            _mgr: &mut EM,
            input: &Self::Input,
        ) -> Result<ExitKind, Error> {
            *state.executions_mut() += 1;

            if input.target_bytes().as_slice().is_empty() {
                Err(Error::empty("Input Empty"))
            } else {
                Ok(ExitKind::Ok)
            }
        }
    }

    #[test]
    fn nop_executor() {
        let empty_input = BytesInput::new(vec![]);
        let nonempty_input = BytesInput::new(vec![1u8]);
        let mut executor = NopExecutor::new();
        let mut fuzzer = NopFuzzer::new();

        let mut state = NopState::new();

        executor
            .run_target(
                &mut fuzzer,
                &mut state,
                &mut NopEventManager::new(),
                &empty_input,
            )
            .unwrap_err();
        executor
            .run_target(
                &mut fuzzer,
                &mut state,
                &mut NopEventManager::new(),
                &nonempty_input,
            )
            .unwrap();
    }
}
