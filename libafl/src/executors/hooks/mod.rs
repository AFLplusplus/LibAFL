use crate::executors::HasObservers;

#[cfg(windows)]
pub mod windows;

#[cfg(all(feature = "std", unix))]
/// The hook for inprocess fork executor
pub mod inprocess_fork;

/// The hook that runs before and after the executor runs the target
pub trait ExecutorHook {
    /// Init this hook
    fn init<E: HasObservers, S>(&mut self, state: &mut S);
    /// The hook that runs before runs the target
    fn pre_exec<E, I, S>(&self, executor: &E, state: &mut S, input: &I);
    /// The hook that runs before runs the target
    fn post_exec<E, I, S>(&self, executor: &E, state: &mut S, input: &I);
}

/// The hook that runs before and after the executor runs the target
pub trait ExecutorHooksTuple {
    /// Init these hooks
    fn init_all<E: HasObservers, S>(&mut self, state: &mut S);
    /// The hooks that runs before runs the target
    fn pre_exec_all<E, I, S>(&self, executor: &E, state: &mut S, input: &I);
    /// The hooks that runs after runs the target
    fn post_exec_all<E, I, S>(&self, executor: &E, state: &mut S, input: &I);
}

impl ExecutorHooksTuple for () {
    fn init_all<E, S>(&mut self, _state: &mut S) {}
    fn pre_exec_all<E, I, S>(&self, _executor: &E, _state: &mut S, _input: &I) {}
    fn post_exec_all<E, I, S>(&self, _executor: &E, _state: &mut S, _input: &I) {}
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

    fn pre_exec_all<E, I, S>(&self, executor: &E, state: &mut S, input: &I) {
        self.0.pre_exec(executor, state, input);
        self.1.pre_exec_all(executor, state, input);
    }

    fn post_exec_all<E, I, S>(&self, executor: &E, state: &mut S, input: &I) {
        self.0.post_exec(executor, state, input);
        self.1.post_exec_all(executor, state, input);
    }
}
