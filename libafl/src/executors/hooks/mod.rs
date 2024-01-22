//! Hooks for the executors.
//! These will be executed right before and after the executor's harness run.

use crate::executors::HasObservers;

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
pub trait ExecutorHook {
    /// Init this hook
    fn init<E: HasObservers, S>(&mut self, state: &mut S);
    /// The hook that runs before runs the target
    fn pre_exec<EM, I, S, Z>(&mut self, fuzzer: &mut Z, state: &mut S, mgr: &mut EM, input: &I);
    /// The hook that runs before runs the target
    fn post_exec<EM, I, S, Z>(&mut self, fuzzer: &mut Z, state: &mut S, mgr: &mut EM, input: &I);
}

/// The hook that runs before and after the executor runs the target
pub trait ExecutorHooksTuple {
    /// Init these hooks
    fn init_all<E: HasObservers, S>(&mut self, state: &mut S);
    /// The hooks that runs before runs the target
    fn pre_exec_all<EM, I, S, Z>(&mut self, fuzzer: &mut Z, state: &mut S, mgr: &mut EM, input: &I);
    /// The hooks that runs after runs the target
    fn post_exec_all<EM, I, S, Z>(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    );
}

impl ExecutorHooksTuple for () {
    fn init_all<E, S>(&mut self, _state: &mut S) {}
    fn pre_exec_all<EM, I, S, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) {
    }
    fn post_exec_all<EM, I, S, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) {
    }
}

impl<Head, Tail> ExecutorHooksTuple for (Head, Tail)
where
    Head: ExecutorHook,
    Tail: ExecutorHooksTuple,
{
    fn init_all<E: HasObservers, S>(&mut self, state: &mut S) {
        self.0.init::<E, S>(state);
        self.1.init_all::<E, S>(state);
    }

    fn pre_exec_all<EM, I, S, Z>(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) {
        self.0.pre_exec(fuzzer, state, mgr, input);
        self.1.pre_exec_all(fuzzer, state, mgr, input);
    }

    fn post_exec_all<EM, I, S, Z>(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) {
        self.0.post_exec(fuzzer, state, mgr, input);
        self.1.post_exec_all(fuzzer, state, mgr, input);
    }
}
