//! Hooks for the executors.
//! These will be executed right before and after the executor's harness run.

use libafl_bolts::Error;

// /// windows crash/timeout handler and asan death context
// #[cfg(windows)]
// pub mod windows;

// /// *nix crash handler
// #[cfg(all(unix, feature = "std"))]
// pub mod unix;

// #[cfg(all(feature = "std", unix))]
// /// The hook for inprocess fork executor
// pub mod inprocess_fork;

/// The hook for inprocess executor
pub mod inprocess;

/// Timer-related stuff
#[cfg(feature = "std")]
pub mod timer;

/// The hook that runs before and after the executor runs the target
///
/// The associated [`ExecutorHook::Context`] type should implement [`Drop`] to perform the
/// post-exec operation, if any. If you don't need to do any, just set `type Context = C;` and
/// return the provided context.
pub trait ExecutorHook<C> {
    /// Context returned by this hook
    type Context;

    /// The hook that runs before the target and returns the context available to subsequent hooks.
    fn pre_exec(&mut self, context: C) -> Result<Self::Context, Error>;

    /// The hook that runs after the target and releases the context available to subsequent hooks.
    fn post_exec(&mut self, context: Self::Context) -> Result<C, Error>;
}

/// Contexts which are able to share the context (e.g., the state)
pub trait HookContext<'a> {
    /// The type of the executor which will be used to perform the upcoming run
    type Executor;
    /// The type of the event manager for this execution
    type EventManager;
    /// The type of the input which will be executed soon
    type Input;
    /// The type of the state for this execution
    type State;
    /// The type of the fuzzer for this execution
    type Fuzzer;

    /// The executor which will be used to perform the upcoming run
    fn executor_mut(&mut self) -> &mut Option<&'a mut Self::Executor>;
    /// The event manager for this execution
    fn manager_mut(&mut self) -> &mut Option<&'a mut Self::EventManager>;
    /// The actual input which will be executed soon
    fn input_mut(&mut self) -> &mut Option<&'a Self::Input>;
    /// The state for this execution
    fn state_mut(&mut self) -> &mut Option<&'a mut Self::State>;
    /// The fuzzer for this execution
    fn fuzzer_mut(&mut self) -> &mut Option<&'a mut Self::Fuzzer>;
}

/// A [`HookContext`] which is created by the end of the hooks tuple list
///
/// While possible to encode this into a trait-backed state machine instead of using [`Option`], it
/// is wildly painful. If we had specialization, this would be really straightforward.
#[derive(Debug)]
pub struct BaseContext<'a, E, EM, I, S, Z> {
    executor: Option<&'a mut E>,
    manager: Option<&'a mut EM>,
    input: Option<&'a I>,
    state: Option<&'a mut S>,
    fuzzer: Option<&'a mut Z>,
}

impl<'a, E, EM, I, S, Z> HookContext<'a> for BaseContext<'a, E, EM, I, S, Z> {
    type Executor = E;
    type EventManager = EM;
    type Input = I;
    type State = S;
    type Fuzzer = Z;

    fn executor_mut(&mut self) -> &mut Option<&'a mut Self::Executor> {
        &mut self.executor
    }

    fn manager_mut(&mut self) -> &mut Option<&'a mut Self::EventManager> {
        &mut self.manager
    }

    fn input_mut(&mut self) -> &mut Option<&'a Self::Input> {
        &mut self.input
    }

    fn state_mut(&mut self) -> &mut Option<&'a mut Self::State> {
        &mut self.state
    }

    fn fuzzer_mut(&mut self) -> &mut Option<&'a mut Self::Fuzzer> {
        &mut self.fuzzer
    }
}

/// The hook that runs before and after the executor runs the target. Contexts are executed *in
/// reverse order* during [`ExecutorHooksTuple::pre_exec_all`] and *in order* when
/// [`Drop::drop`]ed.
pub trait ExecutorHooksTuple<'a, E, EM, I, S, Z> {
    /// The type of context eventually returned by this tuple. When [`Drop::drop`]ed,
    /// post-execution operations are performed.
    type Context;

    /// The hooks that runs before runs the target
    fn pre_exec_all(
        &mut self,
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        mgr: &'a mut EM,
        input: &'a I,
    ) -> Result<Self::Context, Error>;

    /// The hooks that run after the target
    fn post_exec_all(&mut self, context: Self::Context) -> Result<(), Error>;
}

impl<'a, E, EM, I, S, Z> ExecutorHooksTuple<'a, E, EM, I, S, Z> for ()
where
    E: 'a,
    EM: 'a,
    I: 'a,
    S: 'a,
    Z: 'a,
{
    type Context = BaseContext<'a, E, EM, I, S, Z>;

    fn pre_exec_all(
        &mut self,
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        manager: &'a mut EM,
        input: &'a I,
    ) -> Result<Self::Context, Error> {
        Ok(BaseContext {
            executor: Some(executor),
            manager: Some(manager),
            input: Some(input),
            state: Some(state),
            fuzzer: Some(fuzzer),
        })
    }

    fn post_exec_all(&mut self, _context: Self::Context) -> Result<(), Error> {
        Ok(())
    }
}

impl<'a, Head, Tail, E, EM, I, S, Z> ExecutorHooksTuple<'a, E, EM, I, S, Z> for (Head, Tail)
where
    Head: ExecutorHook<Tail::Context>,
    Tail: ExecutorHooksTuple<'a, E, EM, I, S, Z>,
{
    type Context = Head::Context;

    fn pre_exec_all(
        &mut self,
        executor: &'a mut E,
        fuzzer: &'a mut Z,
        state: &'a mut S,
        mgr: &'a mut EM,
        input: &'a I,
    ) -> Result<Self::Context, Error> {
        let context = self.1.pre_exec_all(executor, fuzzer, state, mgr, input)?;
        self.0.pre_exec(context)
    }

    fn post_exec_all(&mut self, context: Self::Context) -> Result<(), Error> {
        let context = self.0.post_exec(context)?;
        self.1.post_exec_all(context)
    }
}

#[cfg(test)]
mod test {
    use core::cell::Cell;

    use libafl_bolts::Error;
    use tuple_list::tuple_list;

    use crate::executors::hooks::{BaseContext, ExecutorHook, ExecutorHooksTuple, HookContext};

    #[test]
    fn simple_hooks() -> Result<(), Error> {
        struct PossessiveHook;
        struct SimpleHook;

        struct PossessiveContext<C>(C);

        impl<'a, C> ExecutorHook<C> for PossessiveHook
        where
            C: HookContext<'a, State = bool, Executor = bool>,
        {
            type Context = PossessiveContext<C>;

            fn pre_exec(&mut self, mut context: C) -> Result<Self::Context, Error> {
                **context.state_mut().as_mut().unwrap() = true;
                Ok(PossessiveContext(context))
            }

            fn post_exec(&mut self, mut context: Self::Context) -> Result<C, Error> {
                **context.0.executor_mut().as_mut().unwrap() = true;
                Ok(context.0)
            }
        }

        impl<'a, C> ExecutorHook<C> for SimpleHook
        where
            C: HookContext<'a, Input = Cell<bool>>,
        {
            type Context = C;

            fn pre_exec(&mut self, mut context: C) -> Result<Self::Context, Error> {
                context.input_mut().as_mut().unwrap().set(true);
                Ok(context)
            }

            fn post_exec(&mut self, context: Self::Context) -> Result<C, Error> {
                Ok(context)
            }
        }

        let mut executor = false;
        let mut fuzzer = ();
        let mut state = false;
        let mut mgr = ();
        let input = Cell::new(false);

        PossessiveHook.pre_exec(BaseContext {
            executor: Some(&mut executor),
            manager: Some(&mut mgr),
            input: Some(&input),
            state: Some(&mut state),
            fuzzer: Some(&mut fuzzer),
        })?;

        let mut hooks = tuple_list!(PossessiveHook);
        // let mut hooks = tuple_list!(PossessiveHook, SimpleHook);
        // let mut hooks = tuple_list!(PossessiveHook, PossessiveHook); <-- cannot compile, because the first possessive hook takes the values

        let context =
            hooks.pre_exec_all(&mut executor, &mut fuzzer, &mut state, &mut mgr, &input)?;

        // state = false; // <-- shouldn't compile

        hooks.post_exec_all(context)?;

        assert!(state);
        assert!(executor);
        assert!(input.get());

        Ok(())
    }
}
