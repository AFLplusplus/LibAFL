//! Hooks for the executors.
//! These will be executed right before and after the executor's harness run.

use crate::executors::Executor;

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

/// The hook that runs before and after the executor runs the target
pub trait ExecutorHook<EM, I, S, Z> {
    type Executor: Executor<EM, I, S, Z>;

    /// The hook that runs before runs the target
    fn pre_exec(&mut self, state: &mut S, input: &I);
    /// The hook that runs before runs the target
    fn post_exec(&mut self, state: &mut S, input: &I);
}

/// The hook that runs before and after the executor runs the target
pub trait ExecutorHooksTuple<E, EM, I, S, Z> {
    /// The hooks that runs before runs the target
    fn pre_exec_all(&mut self, state: &mut S, input: &I);
    /// The hooks that runs after runs the target
    fn post_exec_all(&mut self, state: &mut S, input: &I);
}

impl<E, EM, I, S, Z> ExecutorHooksTuple<E, EM, I, S, Z> for () {
    fn pre_exec_all(&mut self, _state: &mut S, _input: &I) {}
    fn post_exec_all(&mut self, _state: &mut S, _input: &I) {}
}

impl<Head, Tail, EM, I, S, Z> ExecutorHooksTuple<Head::Executor, EM, I, S, Z> for (Head, Tail)
where
    Head: ExecutorHook<EM, I, S, Z>,
    Tail: ExecutorHooksTuple<Head::Executor, EM, I, S, Z>,
{
    fn pre_exec_all(&mut self, state: &mut S, input: &I) {
        self.0.pre_exec(state, input);
        self.1.pre_exec_all(state, input);
    }

    fn post_exec_all(&mut self, state: &mut S, input: &I) {
        self.0.post_exec(state, input);
        self.1.post_exec_all(state, input);
    }
}
