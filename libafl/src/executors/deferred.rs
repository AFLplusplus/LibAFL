//! Deferred executors to allow for asynchronous execution of a target

use alloc::boxed::Box;
use core::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
};
use std::sync::Arc;

use hashbrown::HashMap;
use tokio::{
    runtime::Runtime,
    sync::{
        mpsc,
        mpsc::{Receiver as MpscReceiver, Sender as MpscSender},
        oneshot,
        oneshot::{Sender as OneshotSender, Sender},
        Mutex,
    },
    task::JoinHandle,
};

use crate::{
    events::{Event, EventFirer},
    executors::{ExecutionResult, Executor, ExitKind, HasObservers, WithObservers},
    inputs::{Input, UsesInput},
    observers::{ObserversTuple, UsesObservers},
    state::UsesState,
    Error,
};

/// Execution result which is deferred to when it is available (e.g., if using a remote executor)
pub trait DeferredExecutionResult<E, EM, Z>
where
    E: AsyncExecutor<EM, Z>,
    EM: UsesState,
    Z: UsesState<State = EM::State>,
{
    /// Fetch the result of this execution, pumping events until the result is available
    ///
    /// Note that, while this method accepts a reference to self, it will never be called twice; it
    /// is merely for compatibility with dyn. You should error if the get method is invoked twice by
    /// (for example) using an `Option` to contain the result.
    fn get(
        &mut self,
        rt: &Runtime,
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
    EM: UsesState,
    Z: UsesState<State = EM::State>,
    E::Observers: Clone,
{
    fn get(
        &mut self,
        _: &Runtime,
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
pub trait AsyncExecutor<EM, Z>: UsesObservers<State = EM::State> + Debug
where
    EM: UsesState,
    Z: UsesState<State = EM::State>,
{
    /// Start the target and receive a handle to its deferred result
    fn start_target(
        &mut self,
        rt: &Runtime,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<Box<dyn DeferredExecutionResult<Self, EM, Z>>, Error>;
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
    rt: Runtime,
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
    EM: UsesState + Debug,
    Z: UsesState<State = EM::State> + Debug,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> ExecutionResult {
        let mut deferred = self
            .inner
            .start_target(&self.rt, fuzzer, state, mgr, input)?;
        match deferred.get(&self.rt, &mut self.inner, fuzzer, state, mgr, input) {
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
    E: Executor<EM, Z> + HasObservers<State = EM::State> + 'static,
    EM: UsesState + Debug + 'static,
    Z: UsesState<State = EM::State> + Debug + 'static,
    E::Observers: Clone,
{
    fn start_target(
        &mut self,
        _: &Runtime,
        _: &mut Z,
        _: &mut Self::State,
        _: &mut EM,
        _: &Self::Input,
    ) -> Result<Box<dyn DeferredExecutionResult<Self, EM, Z>>, Error> {
        Ok(Box::new(LazyExecutionResult::new()))
    }
}

/// A single task to be completed by the channel provider
#[derive(Debug)]
pub struct ChannelTask<I> {
    task_id: usize,
    input: I,
}

impl<I> ChannelTask<I> {
    /// Get the task id for this task
    pub fn task_id(&self) -> usize {
        self.task_id
    }

    /// Get the input for this task
    pub fn input(&self) -> &I {
        &self.input
    }

    /// Consume the task into its individual components
    pub fn take(self) -> (usize, I) {
        (self.task_id, self.input)
    }
}

/// A single result or an event sent by the channel provider
#[derive(Debug)]
pub enum ChannelResult<I, OT>
where
    I: Input,
{
    /// An event was received along the channel; forward it to the current job for handling
    Event(Event<I>),
    /// A result was received along the channel; forward it to the associated job
    Result {
        /// ID of the associated task
        task_id: usize,
        /// The result of the execution
        result: Result<(ExitKind, OT), Error>,
    },
}

/// `DeferredExecutionResult` variant used by `ChannelExecutor` to resolve an execution result
struct ChannelDeferredResult<EM, OT>
where
    EM: UsesInput,
{
    events: Arc<Mutex<MpscReceiver<Event<EM::Input>>>>,
    job: JoinHandle<Result<(ExitKind, OT), Error>>,
}

impl<E, EM, Z> DeferredExecutionResult<E, EM, Z> for ChannelDeferredResult<EM, E::Observers>
where
    E: AsyncExecutor<EM, Z>,
    EM: EventFirer,
    Z: UsesState<State = EM::State>,
{
    fn get(
        &mut self,
        rt: &Runtime,
        _: &mut E,
        _: &mut Z,
        state: &mut EM::State,
        mgr: &mut EM,
        _: &EM::Input,
    ) -> Result<(ExitKind, E::Observers), Error> {
        let mut events = rt.block_on(async { self.events.lock().await });
        loop {
            match rt.block_on(async {
                tokio::select! {
                    biased;

                    Some(e) = events.recv() => (Some(e), None),
                    Ok(res) = &mut self.job => (None, Some(res)),
                    else => panic!("The job could not be completed while pumping events")
                }
            }) {
                (Some(e), None) => mgr.fire(state, e)?,
                (None, Some(res)) => {
                    return res;
                }
                _ => unreachable!(),
            }
        }
    }
}

/// An `AsyncExecutor` which submits tasks over a channel. Mostly a utility type for other async
/// executors to be built around.
pub struct ChannelExecutor<EM, OT>
where
    EM: UsesInput,
{
    task_id: usize,
    tx: MpscSender<ChannelTask<EM::Input>>,
    events: Arc<Mutex<MpscReceiver<Event<EM::Input>>>>,
    tasks: Arc<Mutex<HashMap<usize, OneshotSender<Result<(ExitKind, OT), Error>>>>>,
    phantom: PhantomData<*const EM>,
}

impl<EM, OT> ChannelExecutor<EM, OT>
where
    EM: UsesInput,
    OT: Debug + Send + 'static,
    EM::Input: Send + 'static,
{
    /// Create a new channel-backed executor
    ///
    /// `tx` should have a buffer of 1 message, as we want this executor to block when using
    /// `start_target` until the previous task is actually started. This is especially important for
    /// `current_thread` runtimes where the asynchronous events are only driven when `block_on` is
    /// invoked.
    pub fn new(
        rt: &Runtime,
        tx: MpscSender<ChannelTask<EM::Input>>,
        mut rx: MpscReceiver<ChannelResult<EM::Input, OT>>,
    ) -> Self {
        let tasks = Arc::new(Mutex::new(HashMap::new()));
        let cp = tasks.clone();

        let (event_tx, events) = mpsc::channel(1 << 6);

        rt.spawn(async move {
            while let Some(res) = rx.recv().await {
                match res {
                    ChannelResult::Event(e) => event_tx
                        .send(e)
                        .await
                        .expect("Couldn't forward event to event pump."),
                    ChannelResult::Result { task_id, result } => {
                        let res_tx: Sender<Result<(ExitKind, OT), Error>> = cp.lock().await.remove(&task_id).expect(
                            "Received a task result, but there was no associated task to resolve.",
                        );
                        res_tx
                            .send(result)
                            .expect("Couldn't send the result to the associated task.");
                    }
                }
            }
        });
        Self {
            task_id: 0,
            tx,
            events: Arc::new(Mutex::new(events)),
            tasks,
            phantom: PhantomData,
        }
    }
}

impl<EM, OT> UsesObservers for ChannelExecutor<EM, OT>
where
    EM: UsesState,
    OT: ObserversTuple<EM::State>,
{
    type Observers = OT;
}

impl<EM, OT> UsesState for ChannelExecutor<EM, OT>
where
    EM: UsesState,
{
    type State = EM::State;
}

impl<EM, OT> Debug for ChannelExecutor<EM, OT>
where
    EM: UsesInput,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelExecutor")
            .field("task_id", &self.task_id)
            .finish_non_exhaustive()
    }
}

impl<EM, OT, Z> AsyncExecutor<EM, Z> for ChannelExecutor<EM, OT>
where
    EM: EventFirer + Debug + 'static,
    OT: ObserversTuple<EM::State> + Send + 'static,
    Z: UsesState<State = EM::State> + Debug,
    EM::Input: Send + 'static,
{
    fn start_target(
        &mut self,
        rt: &Runtime,
        _fuzzer: &mut Z,
        _state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<Box<dyn DeferredExecutionResult<Self, EM, Z>>, Error> {
        let task_id = self.task_id;
        self.task_id += 1;
        let tasks = self.tasks.clone();
        let tx = self.tx.clone();
        let input = input.clone();
        let (sender, receiver) = oneshot::channel();

        // block until the task is submitted
        // this runtime might be current_thread, in which case we must use block_on to actually
        // drive events in the runtime. The caller is responsible to ensure that tx has a buffer of
        // one so that this block_on will drive their handler to submit the task to whatever
        // execution mechanism they are using
        rt.block_on(async move {
            let not_present = tasks.lock().await.insert(task_id, sender).is_none();
            assert!(not_present, "Tried to create a task which already exists!");
            tx.send(ChannelTask { task_id, input })
                .await
                .expect("Couldn't submit the channel task.");
        });

        // spawn the job in the background
        let job = rt.spawn(async move {
            receiver
                .await
                .expect("Couldn't receive the result for a task.")
        });
        Ok(Box::new(ChannelDeferredResult {
            events: self.events.clone(),
            job,
        }))
    }
}
