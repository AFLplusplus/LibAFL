//! Hooks for the executors.
//! These will be executed right before and after the executor's harness run.

/// windows crash/timeout handler and asan death callback
#[cfg(windows)]
pub mod windows;

// /// *nix crash handler
// #[cfg(all(unix, feature = "std"))]
// pub mod unix;
//
// #[cfg(all(feature = "std", unix))]
// /// The hook for inprocess fork executor
// pub mod inprocess_fork;
//
// /// The hook for inprocess executor
// pub mod inprocess;
//
// /// Timer-related stuff
// #[cfg(feature = "std")]
// pub mod timer;

/// The hook that runs before and after the executor runs the target
///
/// The associated [`ExecutorHook::Callback`] type should implement [`Drop`] to perform the
/// post-exec operation, if any. If you don't need to do any, just set `type Callback = C;` and
/// return the provided callback.
pub trait ExecutorHook<'a, C> {
    /// Callback returned by this hook
    type Callback: Callback<'a>;

    /// The hook that runs before the target and returns the callback which runs the after-target
    /// hook. Hooks which need to access various context data may do so by constraining `C` to
    /// [`NonPossessiveCallback`]. Hooks which only need the input should constrain `C` to
    /// [`Callback`].
    fn pre_exec(&mut self, callback: C) -> Self::Callback;
}

/// General purpose callback for [`ExecutorHook`]
pub trait Callback<'a> {
    /// The type of the input which will be executed soon
    type Input;

    /// The actual input which will be executed soon
    fn input(&self) -> &&'a Self::Input;
}

/// Callbacks which do not take mutable ownership of the context (e.g., the state)
pub trait NonPossessiveCallback<'a>: Callback<'a> {
    /// The type of the executor which will be used to perform the upcoming run
    type Executor;
    /// The type of the event manager for this execution
    type EventManager;
    /// The type of the state for this execution
    type State;
    /// The type of the fuzzer for this execution
    type Fuzzer;

    /// The executor which will be used to perform the upcoming run
    fn executor_mut(&mut self) -> &mut &'a mut Self::Executor;
    /// The event manager for this execution
    fn manager_mut(&mut self) -> &mut &'a mut Self::EventManager;
    /// The state for this execution
    fn state_mut(&mut self) -> &mut &'a mut Self::State;
    /// The fuzzer for this execution
    fn fuzzer_mut(&mut self) -> &mut &'a mut Self::Fuzzer;
}

/// A [`NonPossessiveCallback`] which is created by the end of the hooks tuple list
#[derive(Debug)]
pub struct BaseCompletionCallback<'a, E, EM, I, S, Z> {
    executor: &'a mut E,
    manager: &'a mut EM,
    input: &'a I,
    state: &'a mut S,
    fuzzer: &'a mut Z,
}

impl<'a, E, EM, I, S, Z> Callback<'a> for BaseCompletionCallback<'a, E, EM, I, S, Z> {
    type Input = I;

    fn input(&self) -> &&'a Self::Input {
        &self.input
    }
}

impl<'a, E, EM, I, S, Z> NonPossessiveCallback<'a> for BaseCompletionCallback<'a, E, EM, I, S, Z> {
    type Executor = E;
    type EventManager = EM;
    type State = S;
    type Fuzzer = Z;

    fn executor_mut(&mut self) -> &mut &'a mut Self::Executor {
        &mut self.executor
    }

    fn manager_mut(&mut self) -> &mut &'a mut Self::EventManager {
        &mut self.manager
    }

    fn state_mut(&mut self) -> &mut &'a mut Self::State {
        &mut self.state
    }

    fn fuzzer_mut(&mut self) -> &mut &'a mut Self::Fuzzer {
        &mut self.fuzzer
    }
}

/// The hook that runs before and after the executor runs the target. Callbacks are executed *in
/// reverse order* during [`ExecutorHooksTuple::pre_exec_all`] and *in order* when
/// [`Drop::drop`]ed.
pub trait ExecutorHooksTuple<'a, E, EM, I, S, Z> {
    /// The type of callback eventually returned by this tuple. When [`Drop::drop`]ed,
    /// post-execution operations are performed.
    type Callback;

    /// The hooks that runs before runs the target
    fn pre_exec_all(
        &mut self,
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        mgr: &'a mut EM,
        input: &'a I,
    ) -> Self::Callback;
}

impl<'a, E, EM, I, S, Z> ExecutorHooksTuple<'a, E, EM, I, S, Z> for ()
where
    E: 'a,
    EM: 'a,
    I: 'a,
    S: 'a,
    Z: 'a,
{
    type Callback = BaseCompletionCallback<'a, E, EM, I, S, Z>;

    fn pre_exec_all(
        &mut self,
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        manager: &'a mut EM,
        input: &'a I,
    ) -> Self::Callback {
        BaseCompletionCallback {
            executor,
            manager,
            input,
            state,
            fuzzer,
        }
    }
}

impl<'a, Head, Tail, E, EM, I, S, Z> ExecutorHooksTuple<'a, E, EM, I, S, Z> for (Head, Tail)
where
    Head: ExecutorHook<'a, Tail::Callback>,
    Tail: ExecutorHooksTuple<'a, E, EM, I, S, Z>,
{
    type Callback = Head::Callback;

    fn pre_exec_all(
        &mut self,
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        mgr: &'a mut EM,
        input: &'a I,
    ) -> Self::Callback {
        let callback = self.1.pre_exec_all(executor, fuzzer, state, mgr, input);
        self.0.pre_exec(callback)
    }
}

#[cfg(test)]
mod test {
    use core::{cell::Cell, marker::PhantomData};

    use tuple_list::tuple_list;

    use crate::executors::hooks::{
        Callback, ExecutorHook, ExecutorHooksTuple, NonPossessiveCallback,
    };

    #[test]
    fn simple_hooks() {
        struct PossessiveHook;
        struct SimpleHook;

        struct PossessiveCallback<'a, C>(C, PhantomData<fn() -> &'a ()>)
        where
            C: NonPossessiveCallback<'a, Executor = bool>;

        impl<'a, C> Callback<'a> for PossessiveCallback<'a, C>
        where
            C: NonPossessiveCallback<'a, Executor = bool>,
        {
            type Input = C::Input;

            fn input(&self) -> &&'a Self::Input {
                self.0.input()
            }
        }

        impl<'a, C> ExecutorHook<'a, C> for PossessiveHook
        where
            C: NonPossessiveCallback<'a, State = bool, Executor = bool>,
        {
            type Callback = PossessiveCallback<'a, C>;

            fn pre_exec(&mut self, mut callback: C) -> Self::Callback {
                **callback.state_mut() = true;
                PossessiveCallback(callback, PhantomData)
            }
        }

        impl<'a, C> Drop for PossessiveCallback<'a, C>
        where
            C: NonPossessiveCallback<'a, Executor = bool>,
        {
            fn drop(&mut self) {
                // post-exec operation
                **self.0.executor_mut() = true;
            }
        }

        impl<'a, C> ExecutorHook<'a, C> for SimpleHook
        where
            C: Callback<'a, Input = Cell<bool>>,
        {
            type Callback = C;

            fn pre_exec(&mut self, callback: C) -> Self::Callback {
                callback.input().set(true);
                callback
            }
        }

        let mut executor = false;
        let mut fuzzer = ();
        let mut state = false;
        let mut mgr = ();
        let input = Cell::new(false);

        let mut hooks = tuple_list!(PossessiveHook, SimpleHook);
        // let mut hooks = tuple_list!(PossessiveHook, PossessiveHook); <-- cannot compile, because the first possessive hook takes the values

        let callback = hooks.pre_exec_all(&mut executor, &mut fuzzer, &mut state, &mut mgr, &input);

        // state = false; // <-- shouldn't compile

        drop(callback);

        assert!(state);
        assert!(executor);
        assert!(input.get());
    }
}
