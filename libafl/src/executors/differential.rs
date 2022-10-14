//! Executor for differential fuzzing.
//! It wraps two executors that will be run after each other with the same input.
//! In comparison to the [`crate::executors::CombinedExecutor`] it also runs the secondary executor in `run_target`.
//!
use core::fmt::Debug;

use crate::{
    executors::{Executor, ExitKind, HasObservers},
    state::State,
    Error,
};

/// A [`DiffExecutor`] wraps a primary executor, forwarding its methods, and a secondary one
#[derive(Debug)]
pub struct DiffExecutor<A, B>
where
    A: Debug,
    B: Debug,
{
    primary: A,
    secondary: B,
}

impl<A, B> DiffExecutor<A, B>
where
    A: Debug,
    B: Debug,
{
    /// Create a new `DiffExecutor`, wrapping the given `executor`s.
    pub fn new<EM, S, Z>(primary: A, secondary: B) -> Self
    where
        A: Executor<EM, S, Z>,
        B: Executor<EM, S, Z>,
        Z: Sized,
    {
        Self { primary, secondary }
    }

    /// Retrieve the primary `Executor` that is wrapped by this `DiffExecutor`.
    pub fn primary(&mut self) -> &mut A {
        &mut self.primary
    }

    /// Retrieve the secondary `Executor` that is wrapped by this `DiffExecutor`.
    pub fn secondary(&mut self) -> &mut B {
        &mut self.secondary
    }
}

impl<A, B, EM, S, Z> Executor<EM, S, Z> for DiffExecutor<A, B>
where
    A: Executor<EM, S, Z>,
    B: Executor<EM, S, Z>,
    S: State,
    Z: Sized,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &S::Input,
    ) -> Result<ExitKind, Error> {
        let ret1 = self.primary.run_target(fuzzer, state, mgr, input)?;
        self.primary.post_run_reset();
        let ret2 = self.secondary.run_target(fuzzer, state, mgr, input)?;
        self.secondary.post_run_reset();
        if ret1 == ret2 {
            Ok(ret1)
        } else {
            // We found a diff in the exit codes!
            Ok(ExitKind::Diff {
                primary: ret1.into(),
                secondary: ret2.into(),
            })
        }
    }
}

impl<A, B> HasObservers for DiffExecutor<A, B>
where
    A: HasObservers,
    B: HasObservers<State = A::State, Observers = A::Observers>,
{
    type State = A::State;

    type Observers = A::Observers;

    #[inline]
    fn observers(&self) -> &Self::Observers {
        self.primary.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut Self::Observers {
        self.primary.observers_mut()
    }
}
