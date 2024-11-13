//! Hooks for the executors.
//! These will be executed right before and after the executor's harness run.

use crate::{executors::HasObservers, inputs::UsesInput};

/// windows crash/timeout handler and asan death callback
#[cfg(windows)]
pub mod windows;

/// *nix crash handler
#[cfg(all(unix, feature = "std"))]
pub mod unix;

#[cfg(all(feature = "std", unix))]
/// The hook for inprocess fork executor
pub mod inprocess_fork;

/// The hook for inprocess executor
pub mod inprocess;

/// Timer-related stuff
#[cfg(feature = "std")]
pub mod timer;

/// Intel Processor Trace (PT)
#[cfg(all(feature = "intel_pt", target_os = "linux"))]
pub mod intel_pt;

/// The hook that runs before and after the executor runs the target
pub trait ExecutorHook<S>
where
    S: UsesInput,
{
    /// Init this hook
    fn init<E: HasObservers>(&mut self, state: &mut S);
    /// The hook that runs before runs the target
    fn pre_exec(&mut self, state: &mut S, input: &S::Input);
    /// The hook that runs before runs the target
    fn post_exec(&mut self, state: &mut S, input: &S::Input);
}

/// The hook that runs before and after the executor runs the target
pub trait ExecutorHooksTuple<S>
where
    S: UsesInput,
{
    /// Init these hooks
    fn init_all<E: HasObservers>(&mut self, state: &mut S);
    /// The hooks that runs before runs the target
    fn pre_exec_all(&mut self, state: &mut S, input: &S::Input);
    /// The hooks that runs after runs the target
    fn post_exec_all(&mut self, state: &mut S, input: &S::Input);
}

impl<S> ExecutorHooksTuple<S> for ()
where
    S: UsesInput,
{
    fn init_all<E: HasObservers>(&mut self, _state: &mut S) {}
    fn pre_exec_all(&mut self, _state: &mut S, _input: &S::Input) {}
    fn post_exec_all(&mut self, _state: &mut S, _input: &S::Input) {}
}

impl<Head, Tail, S> ExecutorHooksTuple<S> for (Head, Tail)
where
    S: UsesInput,
    Head: ExecutorHook<S>,
    Tail: ExecutorHooksTuple<S>,
{
    fn init_all<E: HasObservers>(&mut self, state: &mut S) {
        self.0.init::<E>(state);
        self.1.init_all::<E>(state);
    }

    fn pre_exec_all(&mut self, state: &mut S, input: &S::Input) {
        self.0.pre_exec(state, input);
        self.1.pre_exec_all(state, input);
    }

    fn post_exec_all(&mut self, state: &mut S, input: &S::Input) {
        self.0.post_exec(state, input);
        self.1.post_exec_all(state, input);
    }
}
