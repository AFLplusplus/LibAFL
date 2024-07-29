//! Hooks for the executors.
//! These will be executed right before and after the executor's harness run.

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
pub trait ExecutorHook<I, S> {
    /// The hook that runs before runs the target
    fn pre_exec(&mut self, state: &mut S, input: &I);
    /// The hook that runs before runs the target
    fn post_exec(&mut self, state: &mut S, input: &I);
}

/// The hook that runs before and after the executor runs the target
pub trait ExecutorHooksTuple<I, S> {
    /// The hooks that runs before runs the target
    fn pre_exec_all(&mut self, state: &mut S, input: &I);
    /// The hooks that runs after runs the target
    fn post_exec_all(&mut self, state: &mut S, input: &I);
}

impl<I, S> ExecutorHooksTuple<I, S> for () {
    fn pre_exec_all(&mut self, _state: &mut S, _input: &I) {}
    fn post_exec_all(&mut self, _state: &mut S, _input: &I) {}
}

impl<Head, Tail, I, S> ExecutorHooksTuple<I, S> for (Head, Tail)
where
    Head: ExecutorHook<I, S>,
    Tail: ExecutorHooksTuple<I, S>,
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
