//! Executors take input, and run it in the target.

#[cfg(unix)]
use alloc::vec::Vec;
use core::{fmt::Debug, time::Duration};

pub use combined::CombinedExecutor;
#[cfg(all(feature = "std", unix))]
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

use crate::{state::UsesState, Error};

pub mod combined;
#[cfg(all(feature = "std", unix))]
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
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

/// How one of the diffing executions finished.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(
    any(not(feature = "serdeany_autoreg"), miri),
    allow(clippy::unsafe_derive_deserialize)
)] // for SerdeAny
pub enum DiffExitKind {
    /// The run exited normally.
    Ok,
    /// The run resulted in a target crash.
    Crash,
    /// The run hit an out of memory error.
    Oom,
    /// The run timed out
    Timeout,
    /// One of the executors itelf repots a differential, we can't go into further details.
    Diff,
    // The run resulted in a custom `ExitKind`.
    // Custom(Box<dyn SerdeAny>),
}

libafl_bolts::impl_serdeany!(ExitKind);

impl From<ExitKind> for DiffExitKind {
    fn from(exitkind: ExitKind) -> Self {
        match exitkind {
            ExitKind::Ok => DiffExitKind::Ok,
            ExitKind::Crash => DiffExitKind::Crash,
            ExitKind::Oom => DiffExitKind::Oom,
            ExitKind::Timeout => DiffExitKind::Timeout,
            ExitKind::Diff { .. } => DiffExitKind::Diff,
        }
    }
}

libafl_bolts::impl_serdeany!(DiffExitKind);

/// Holds a tuple of Observers
pub trait HasObservers {
    /// The observer
    type Observers;

    /// Get the linked observers
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers>;

    /// Get the linked observers (mutable)
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers>;
}

/// An executor takes the given inputs, and runs the harness/target.
pub trait Executor<EM, Z>: UsesState
where
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
{
    /// Instruct the target about the input and run
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error>;
}

/// A trait that allows to get/set an `Executor`'s timeout thresold
pub trait HasTimeout {
    /// Get a timeout
    fn timeout(&self) -> Duration;

    /// Set timeout
    fn set_timeout(&mut self, timeout: Duration);
}

/// The common signals we want to handle
#[cfg(unix)]
#[inline]
#[must_use]
pub fn common_signals() -> Vec<Signal> {
    vec![
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
    ]
}

#[cfg(test)]
mod test {
    use core::marker::PhantomData;

    use libafl_bolts::{AsSlice, Error};

    use crate::{
        events::NopEventManager,
        executors::{Executor, ExitKind},
        fuzzer::NopFuzzer,
        inputs::{BytesInput, HasTargetBytes},
        state::{HasExecutions, NopState, State, UsesState},
    };

    /// A simple executor that does nothing.
    /// If intput len is 0, `run_target` will return Err
    #[derive(Debug)]
    pub struct NopExecutor<S> {
        phantom: PhantomData<S>,
    }

    impl<S> NopExecutor<S> {
        /// Creates a new [`NopExecutor`]
        #[must_use]
        pub fn new() -> Self {
            Self {
                phantom: PhantomData,
            }
        }
    }

    impl<S> Default for NopExecutor<S> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<S> UsesState for NopExecutor<S>
    where
        S: State,
    {
        type State = S;
    }

    impl<EM, S, Z> Executor<EM, Z> for NopExecutor<S>
    where
        EM: UsesState<State = S>,
        S: State + HasExecutions,
        S::Input: HasTargetBytes,
        Z: UsesState<State = S>,
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
