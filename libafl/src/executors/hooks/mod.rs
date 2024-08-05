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
pub trait ExecutorHook<E, EM, I, S, Z> {
    /// The hook that runs before the target
    fn pre_exec(
        &mut self,
        executor: &mut E,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &S,
    );

    /// The hook that runs after the target
    fn post_exec(
        &mut self,
        executor: &mut E,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &S,
    );
}

/// The hook that runs before and after the executor runs the target, controlling the use of the
/// provided data via ownership
pub trait ConsumingExecutorHook<E, EM, I, S, Z> {
    type Handle<'a>: ConsumedExecutorHandle<'a>;

    /// The hook that runs before runs the target
    fn pre_exec<'a>(
        &mut self,
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        mgr: &'a mut EM,
        input: &'a I,
    ) -> Self::Handle<'a>;

    /// The hook that runs before runs the target
    fn post_exec(&mut self, release: Self::Handle);
}

pub trait ConsumedExecutorHandle<'a> {
    type Executor;
    type EventManager;
    type Input;
    type State;
    type Fuzzer;

    fn decompose(
        self,
    ) -> (
        &'a mut Self::Executor,
        &'a mut Self::Fuzzer,
        &'a mut Self::State,
        &'a mut Self::EventManager,
        &'a Self::Input,
    );
}

pub struct DefaultExecutorHandle<'a, E, EM, I, S, Z> {}

/// The hook that runs before and after the executor runs the target
pub trait ExecutorHooksTuple<E, EM, I, S, Z> {
    type Handle<'a>;

    /// The hooks that runs before runs the target
    fn pre_exec_all<'a>(
        &mut self,
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        mgr: &'a mut EM,
        input: &'a I,
    ) -> Self::Handle<'a>;

    /// The hooks that runs after runs the target
    fn post_exec_all(&mut self, release: Self::Handle);
}

impl<E, EM, I, S, Z> ExecutorHooksTuple<E, EM, I, S, Z> for () {
    type Handle<'a> = (&'a mut E, &'a mut Z, &'a mut S, &'a mut EM, &'a I);

    fn pre_exec_all<'a>(
        &mut self,
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        mgr: &'a mut EM,
        input: &'a I,
    ) -> Self::Handle<'a> {
        (executor, fuzzer, state, mgr, input)
    }

    fn post_exec_all(&mut self, _release: Self::Handle) {}
}

impl<CEH, E, EM, I, S, Z> ExecutorHooksTuple<E, EM, I, S, Z> for (CEH, ())
where
    CEH: ConsumingExecutorHook<E, EM, I, S, Z>,
{
    type Handle<'a> = CEH::Handle<'a>;

    fn pre_exec_all<'a>(
        &mut self,
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        mgr: &'a mut EM,
        input: &'a I,
    ) -> Self::Handle<'a> {
        self.0.pre_exec(executor, fuzzer, state, mgr, input)
    }

    fn post_exec_all(&mut self, release: Self::Handle) {
        self.0.post_exec(release)
    }
}

impl<Head, Tail, E, EM, I, S, Z> ExecutorHooksTuple<E, EM, I, S, Z> for (Head, Tail)
where
    Head: ExecutorHook<E, EM, I, S, Z>,
    Tail: ExecutorHooksTuple<E, EM, I, S, Z>,
{
    fn pre_exec_all(
        &mut self,
        executor: &mut E,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &S,
    ) {
        self.0.pre_exec(executor, fuzzer, state, mgr, input);
        self.1.pre_exec_all(executor, fuzzer, state, mgr, input);
    }

    fn post_exec_all(
        &mut self,
        executor: &mut E,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &S,
    ) {
        self.0.post_exec(executor, fuzzer, state, mgr, input);
        self.1.post_exec_all(executor, fuzzer, state, mgr, input);
    }
}
