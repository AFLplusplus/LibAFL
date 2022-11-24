//! Deferred executors to allow for asynchronous execution of a target

use alloc::boxed::Box;
use core::{fmt::Debug, marker::PhantomData};

use crate::{
    executors::{ExecutionResult, Executor, ExitKind, HasObservers, WithObservers},
    observers::{ObserversTuple, UsesObservers},
    state::UsesState,
    Error,
};

/// Execution result which is deferred to when it is available (e.g., if using a remote executor)
pub trait DeferredExecutionResult<E, EM, Z>
where
    E: AsyncExecutor<EM, Z>,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
{
    /// Continuously pump events until the result is received
    ///
    /// By default, this does nothing
    #[allow(unused_variables)]
    fn pump_events(&self, mgr: &mut EM) -> Result<(), Error> {
        Ok(())
    }

    /// Fetch the result of this execution
    ///
    /// Note that, while this method accepts a reference to self, it will never be called twice; it
    /// is merely for compatibility with dyn. You should error if the get method is invoked twice by
    /// (for example) using an `Option` to contain the result.
    fn get(
        &mut self,
        executor: &mut E,
        fuzzer: &mut Z,
        state: &mut E::State,
        mgr: &mut EM,
        input: &E::Input,
    ) -> Result<(ExitKind, E::Observers), Error>;
}

/// Execution result which is computed lazily rather than now, primarily for sync/async interop.
#[derive(Debug)]
pub struct LazyExecutionResult<E, EM, Z> {
    phantom: PhantomData<(*const E, *const EM, *const Z)>,
}

impl<E, EM, Z> LazyExecutionResult<E, EM, Z> {
    /// Create a `LazyExecutionResult`
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl<E, EM, Z> DeferredExecutionResult<E, EM, Z> for LazyExecutionResult<E, EM, Z>
where
    E: AsyncExecutor<EM, Z> + Executor<EM, Z> + HasObservers,
    EM: UsesState<State = E::State>,
    Z: UsesState<State = E::State>,
    E::Observers: Clone,
{
    fn get(
        &mut self,
        executor: &mut E,
        fuzzer: &mut Z,
        state: &mut E::State,
        mgr: &mut EM,
        input: &E::Input,
    ) -> Result<(ExitKind, E::Observers), Error> {
        match executor.run_target(fuzzer, state, mgr, input) {
            Ok(exit) => Ok((exit, executor.observers().clone())),
            Err(e) => Err(e),
        }
    }
}

/// An executor which defers the result until the executor is complete, asynchronously
///
/// There is a blanket impl for all `Executor`s to allow for interoperability between asynchronous
/// and synchronous executors, but it performs an extra clone and will therefore be slower. You
/// should prefer to use synchronous executors where possible.
pub trait AsyncExecutor<EM, Z>: UsesObservers + Debug
where
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
{
    /// Start the target and receive a handle to its deferred result
    fn start_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Box<dyn DeferredExecutionResult<Self, EM, Z>>;
}

/// Bridge for interoperability from async => sync executors.
///
/// You should *almost always* prefer to use an asynchronous fuzzer pipeline and bridge
/// sync => async instead. Asynchronous executors will likely prefer batch-oriented workloads than
/// single workloads, but synchronous pipelines will execute only one testcase at a time.
#[derive(Debug)]
pub struct AsyncBridge<E, EM, Z>
where
    E: UsesObservers,
{
    inner: E,
    observers: Option<E::Observers>,
    phantom: PhantomData<(*const EM, *const Z)>,
}

impl<E, EM, Z> UsesState for AsyncBridge<E, EM, Z>
where
    E: UsesObservers,
{
    type State = E::State;
}

impl<E, EM, Z> Executor<EM, Z> for AsyncBridge<E, EM, Z>
where
    E: AsyncExecutor<EM, Z>,
    EM: UsesState<State = Self::State> + Debug,
    Z: UsesState<State = Self::State> + Debug,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> ExecutionResult {
        let mut deferred = self.inner.start_target(fuzzer, state, mgr, input);
        deferred.pump_events(mgr)?;
        match deferred.get(&mut self.inner, fuzzer, state, mgr, input) {
            Ok((exit, obs)) => {
                self.observers = Some(obs);
                Ok(exit)
            }
            Err(e) => Err(e),
        }
    }

    fn with_observers<OT>(self, _: OT) -> WithObservers<Self, OT>
    where
        Self: Sized,
        OT: ObserversTuple<Self::State>,
    {
        unimplemented!("Cannot create a WithObservers for an AsyncBridge!")
    }
}

// blanket impl to allow all existing executors to be used as async executors by lazily computing
// their result
impl<E, EM, Z> AsyncExecutor<EM, Z> for E
where
    E: Executor<EM, Z> + HasObservers + 'static,
    EM: UsesState<State = Self::State> + Debug + 'static,
    Z: UsesState<State = Self::State> + Debug + 'static,
    E::Observers: Clone,
{
    fn start_target(
        &mut self,
        _: &mut Z,
        _: &mut Self::State,
        _: &mut EM,
        _: &Self::Input,
    ) -> Box<dyn DeferredExecutionResult<Self, EM, Z>> {
        Box::new(LazyExecutionResult::new())
    }
}
