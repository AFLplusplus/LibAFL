//! The [`InProcessExecutor`] is a libfuzzer-like executor, that will simply call a function.
//! It should usually be paired with extra error-handling, such as a restarting event manager, to be effective.
//!
//! Needs the `fork` feature flag.
#![allow(clippy::needless_pass_by_value)]

use alloc::boxed::Box;
use core::{
    borrow::BorrowMut,
    ffi::c_void,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ptr::{self, addr_of_mut, null, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
    time::Duration,
};

use libafl_bolts::tuples::{tuple_list, Merge};
#[cfg(windows)]
use windows::Win32::System::Threading::SetThreadStackGuarantee;

#[cfg(all(feature = "std", target_os = "linux"))]
use crate::executors::hooks::inprocess::HasTimeout;
#[cfg(all(windows, feature = "std"))]
use crate::executors::hooks::inprocess::HasTimeout;
use crate::{
    corpus::{Corpus, Testcase},
    events::{Event, EventFirer, EventRestarter},
    executors::{
        hooks::{
            inprocess::{InProcessHooks, GLOBAL_STATE},
            ExecutorHooksTuple,
        },
        Executor, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::{ObserversTuple, UsesObservers},
    state::{HasCorpus, HasExecutions, HasMetadata, HasSolutions, State, UsesState},
    Error,
};

/// The process executor simply calls a target function, as mutable reference to a closure
pub type InProcessExecutor<'a, H, OT, S> = GenericInProcessExecutor<H, &'a mut H, (), OT, S>;

/// The inprocess executor that allows hooks
pub type HookableInProcessExecutor<'a, H, HT, OT, S> =
    GenericInProcessExecutor<H, &'a mut H, HT, OT, S>;
/// The process executor simply calls a target function, as boxed `FnMut` trait object
pub type OwnedInProcessExecutor<OT, S> = GenericInProcessExecutor<
    dyn FnMut(&<S as UsesInput>::Input) -> ExitKind,
    Box<dyn FnMut(&<S as UsesInput>::Input) -> ExitKind>,
    (),
    OT,
    S,
>;

/// The inmem executor simply calls a target function, then returns afterwards.
#[allow(dead_code)]
pub struct GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
{
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: HB,
    /// The observers, observing each run
    observers: OT,
    // Crash and timeout hah
    hooks: (InProcessHooks, HT),
    phantom: PhantomData<(S, *const H)>,
}

impl<H, HB, HT, OT, S> Debug for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S> + Debug,
    S: State,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenericInProcessExecutor")
            .field("harness_fn", &"<fn>")
            .field("observers", &self.observers)
            .finish_non_exhaustive()
    }
}

impl<H, HB, HT, OT, S> UsesState for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
{
    type State = S;
}

impl<H, HB, HT, OT, S> UsesObservers for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
{
    type Observers = OT;
}

impl<EM, H, HB, HT, OT, S, Z> Executor<EM, Z> for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    EM: UsesState<State = S>,
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State + HasExecutions,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut Self::State,
        mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;
        self.enter_target(fuzzer, state, mgr, input);
        self.hooks.pre_exec_all(fuzzer, state, mgr, input);

        let ret = (self.harness_fn.borrow_mut())(input);

        self.hooks.post_exec_all(fuzzer, state, mgr, input);
        self.leave_target(fuzzer, state, mgr, input);
        Ok(ret)
    }
}

impl<H, HB, HT, OT, S> HasObservers for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
{
    #[inline]
    fn observers(&self) -> &OT {
        &self.observers
    }

    #[inline]
    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
impl<H, HB, HT, OT, S> GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State,
{
    /// This function marks the boundary between the fuzzer and the target
    #[inline]
    pub fn enter_target<EM, Z>(
        &mut self,
        fuzzer: &mut Z,
        state: &mut <Self as UsesState>::State,
        mgr: &mut EM,
        input: &<Self as UsesInput>::Input,
    ) {
        unsafe {
            let data = addr_of_mut!(GLOBAL_STATE);
            write_volatile(
                addr_of_mut!((*data).current_input_ptr),
                ptr::from_ref(input) as *const c_void,
            );
            write_volatile(
                addr_of_mut!((*data).executor_ptr),
                ptr::from_ref(self) as *const c_void,
            );
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(
                addr_of_mut!((*data).state_ptr),
                ptr::from_mut(state) as *mut c_void,
            );
            write_volatile(
                addr_of_mut!((*data).event_mgr_ptr),
                ptr::from_mut(mgr) as *mut c_void,
            );
            write_volatile(
                addr_of_mut!((*data).fuzzer_ptr),
                ptr::from_mut(fuzzer) as *mut c_void,
            );
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// This function marks the boundary between the fuzzer and the target
    #[inline]
    pub fn leave_target<EM, Z>(
        &mut self,
        _fuzzer: &mut Z,
        _state: &mut <Self as UsesState>::State,
        _mgr: &mut EM,
        _input: &<Self as UsesInput>::Input,
    ) {
        unsafe {
            let data = addr_of_mut!(GLOBAL_STATE);

            write_volatile(addr_of_mut!((*data).current_input_ptr), null());
            compiler_fence(Ordering::SeqCst);
        }
    }
}

impl<'a, H, OT, S> InProcessExecutor<'a, H, OT, S>
where
    H: FnMut(&<S as UsesInput>::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: HasExecutions + HasSolutions + HasCorpus + State,
{
    /// Create a new in mem executor with the default timeout (5 sec)
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        Self::with_timeout_generic(
            tuple_list!(),
            harness_fn,
            observers,
            fuzzer,
            state,
            event_mgr,
            Duration::from_millis(5000),
        )
    }

    /// Create a new in mem executor with the default timeout and use batch mode (5 sec)
    /// Do not use batched mode timeouts with cmplog cores. It is not supported
    #[cfg(all(feature = "std", target_os = "linux"))]
    pub fn batched_timeouts<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        exec_tmout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let mut me = Self::with_timeout_generic(
            tuple_list!(),
            harness_fn,
            observers,
            fuzzer,
            state,
            event_mgr,
            exec_tmout,
        )?;
        me.hooks_mut().0.timer_mut().batch_mode = true;
        Ok(me)
    }

    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `user_hooks` - the hooks run before and after the harness's execution
    /// * `harness_fn` - the harness, executing the function
    /// * `observers` - the observers observing the target during execution
    /// This may return an error on unix, if signal handler setup fails
    pub fn with_timeout<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let default = InProcessHooks::new::<Self, EM, OF, Z>(timeout)?;
        let mut hooks = tuple_list!(default).merge(tuple_list!());
        hooks.init_all::<Self, S>(state);

        #[cfg(windows)]
        // Some initialization necessary for windows.
        unsafe {
            /*
                See https://github.com/AFLplusplus/LibAFL/pull/403
                This one reserves certain amount of memory for the stack.
                If stack overflow happens during fuzzing on windows, the program is transferred to our exception handler for windows.
                However, if we run out of the stack memory again in this exception handler, we'll crash with STATUS_ACCESS_VIOLATION.
                We need this API call because with the llmp_compression
                feature enabled, the exception handler uses a lot of stack memory (in the compression lib code) on release build.
                As far as I have observed, the compression uses around 0x10000 bytes, but for safety let's just reserve 0x20000 bytes for our exception handlers.
                This number 0x20000 could vary depending on the compilers optimization for future compression library changes.
            */
            let mut stack_reserved = 0x20000;
            SetThreadStackGuarantee(&mut stack_reserved)?;
        }

        #[cfg(all(feature = "std", windows))]
        {
            // set timeout for the handler
            *hooks.0.millis_sec_mut() = timeout.as_millis() as i64;
        }

        Ok(Self {
            harness_fn,
            observers,
            hooks,
            phantom: PhantomData,
        })
    }
}

impl<H, HB, HT, OT, S> GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&<S as UsesInput>::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: HasExecutions + HasSolutions + HasCorpus + State,
{
    /// Create a new in mem executor with the default timeout (5 sec)
    pub fn generic<EM, OF, Z>(
        user_hooks: HT,
        harness_fn: HB,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        Self::with_timeout_generic(
            user_hooks,
            harness_fn,
            observers,
            fuzzer,
            state,
            event_mgr,
            Duration::from_millis(5000),
        )
    }

    /// Create a new in mem executor with the default timeout and use batch mode(5 sec)
    #[cfg(all(feature = "std", target_os = "linux"))]
    pub fn batched_timeout_generic<EM, OF, Z>(
        user_hooks: HT,
        harness_fn: HB,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        exec_tmout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let mut me = Self::with_timeout_generic(
            user_hooks, harness_fn, observers, fuzzer, state, event_mgr, exec_tmout,
        )?;
        me.hooks_mut().0.timer_mut().batch_mode = true;
        Ok(me)
    }

    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `user_hooks` - the hooks run before and after the harness's execution
    /// * `harness_fn` - the harness, executing the function
    /// * `observers` - the observers observing the target during execution
    /// This may return an error on unix, if signal handler setup fails
    pub fn with_timeout_generic<EM, OF, Z>(
        user_hooks: HT,
        harness_fn: HB,
        observers: OT,
        _fuzzer: &mut Z,
        state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let default = InProcessHooks::new::<Self, EM, OF, Z>(timeout)?;
        let mut hooks = tuple_list!(default).merge(user_hooks);
        hooks.init_all::<Self, S>(state);

        #[cfg(windows)]
        // Some initialization necessary for windows.
        unsafe {
            /*
                See https://github.com/AFLplusplus/LibAFL/pull/403
                This one reserves certain amount of memory for the stack.
                If stack overflow happens during fuzzing on windows, the program is transferred to our exception handler for windows.
                However, if we run out of the stack memory again in this exception handler, we'll crash with STATUS_ACCESS_VIOLATION.
                We need this API call because with the llmp_compression
                feature enabled, the exception handler uses a lot of stack memory (in the compression lib code) on release build.
                As far as I have observed, the compression uses around 0x10000 bytes, but for safety let's just reserve 0x20000 bytes for our exception handlers.
                This number 0x20000 could vary depending on the compilers optimization for future compression library changes.
            */
            let mut stack_reserved = 0x20000;
            SetThreadStackGuarantee(&mut stack_reserved)?;
        }

        #[cfg(all(feature = "std", windows))]
        {
            // set timeout for the handler
            *hooks.0.millis_sec_mut() = timeout.as_millis() as i64;
        }

        Ok(Self {
            harness_fn,
            observers,
            hooks,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> &H {
        self.harness_fn.borrow()
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness_fn.borrow_mut()
    }

    /// The inprocess handlers
    #[inline]
    pub fn hooks(&self) -> &(InProcessHooks, HT) {
        &self.hooks
    }

    /// The inprocess handlers (mutable)
    #[inline]
    pub fn hooks_mut(&mut self) -> &mut (InProcessHooks, HT) {
        &mut self.hooks
    }
}

/// The struct has [`InProcessHooks`].
pub trait HasInProcessHooks {
    /// Get the in-process handlers.
    fn inprocess_hooks(&self) -> &InProcessHooks;

    /// Get the mut in-process handlers.
    fn inprocess_hooks_mut(&mut self) -> &mut InProcessHooks;
}

impl<H, HB, HT, OT, S> HasInProcessHooks for GenericInProcessExecutor<H, HB, HT, OT, S>
where
    H: FnMut(&<S as UsesInput>::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    HT: ExecutorHooksTuple,
    OT: ObserversTuple<S>,
    S: State + HasExecutions + HasSolutions + HasCorpus,
{
    /// the timeout handler
    #[inline]
    fn inprocess_hooks(&self) -> &InProcessHooks {
        &self.hooks.0
    }

    /// the timeout handler
    #[inline]
    fn inprocess_hooks_mut(&mut self) -> &mut InProcessHooks {
        &mut self.hooks.0
    }
}

#[inline]
#[allow(clippy::too_many_arguments)]
/// Save state if it is an objective
pub fn run_observers_and_save_state<E, EM, OF, Z>(
    executor: &mut E,
    state: &mut E::State,
    input: &<E::State as UsesInput>::Input,
    fuzzer: &mut Z,
    event_mgr: &mut EM,
    exitkind: ExitKind,
) where
    E: HasObservers,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<E::State>,
    E::State: HasExecutions + HasSolutions + HasCorpus,
    Z: HasObjective<Objective = OF, State = E::State>,
{
    let observers = executor.observers_mut();

    observers
        .post_exec_all(state, input, &exitkind)
        .expect("Observers post_exec_all failed");

    let interesting = fuzzer
        .objective_mut()
        .is_interesting(state, event_mgr, input, observers, &exitkind)
        .expect("In run_observers_and_save_state objective failure.");

    if interesting {
        let mut new_testcase = Testcase::with_executions(input.clone(), *state.executions());
        new_testcase.add_metadata(exitkind);
        new_testcase.set_parent_id_optional(*state.corpus().current());
        fuzzer
            .objective_mut()
            .append_metadata(state, observers, &mut new_testcase)
            .expect("Failed adding metadata");
        state
            .solutions_mut()
            .add(new_testcase)
            .expect("In run_observers_and_save_state solutions failure.");
        event_mgr
            .fire(
                state,
                Event::Objective {
                    objective_size: state.solutions().count(),
                },
            )
            .expect("Could not save state in run_observers_and_save_state");
    }

    // Serialize the state and wait safely for the broker to read pending messages
    event_mgr.on_restart(state).unwrap();

    log::info!("Bye!");
}

// TODO remove this after executor refactor and libafl qemu new executor
/// Expose a version of the crash handler that can be called from e.g. an emulator
///
/// # Safety
/// This will directly access `GLOBAL_STATE` and related data pointers
#[cfg(any(unix, feature = "std"))]
pub unsafe fn generic_inproc_crash_handler<E, EM, OF, Z>()
where
    E: Executor<EM, Z> + HasObservers,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<E::State>,
    E::State: HasExecutions + HasSolutions + HasCorpus,
    Z: HasObjective<Objective = OF, State = E::State>,
{
    let data = addr_of_mut!(GLOBAL_STATE);
    let in_handler = (*data).set_in_handler(true);

    if (*data).is_valid() {
        let executor = (*data).executor_mut::<E>();
        let state = (*data).state_mut::<E::State>();
        let event_mgr = (*data).event_mgr_mut::<EM>();
        let fuzzer = (*data).fuzzer_mut::<Z>();
        let input = (*data).take_current_input::<<E::State as UsesInput>::Input>();

        run_observers_and_save_state::<E, EM, OF, Z>(
            executor,
            state,
            input,
            fuzzer,
            event_mgr,
            ExitKind::Crash,
        );
    }

    (*data).set_in_handler(in_handler);
}

#[cfg(test)]
mod tests {
    use libafl_bolts::tuples::tuple_list;

    use crate::{
        corpus::InMemoryCorpus,
        events::NopEventManager,
        executors::{Executor, ExitKind, InProcessExecutor},
        feedbacks::CrashFeedback,
        inputs::{NopInput, UsesInput},
        schedulers::RandScheduler,
        state::StdState,
        StdFuzzer,
    };

    impl UsesInput for () {
        type Input = NopInput;
    }

    #[test]
    #[allow(clippy::let_unit_value)]
    fn test_inmem_exec() {
        let mut harness = |_buf: &NopInput| ExitKind::Ok;
        let rand = libafl_bolts::rands::XkcdRand::new();
        let corpus = InMemoryCorpus::<NopInput>::new();
        let solutions = InMemoryCorpus::new();
        let mut objective = CrashFeedback::new();
        let mut feedback = tuple_list!();
        let sche = RandScheduler::new();
        let mut mgr = NopEventManager::new();
        let mut state =
            StdState::new(rand, corpus, solutions, &mut feedback, &mut objective).unwrap();
        let mut fuzzer = StdFuzzer::<_, _, _, ()>::new(sche, feedback, objective);

        let mut in_process_executor = InProcessExecutor::new(
            &mut harness,
            tuple_list!(),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .unwrap();
        let input = NopInput {};
        in_process_executor
            .run_target(&mut fuzzer, &mut state, &mut mgr, &input)
            .unwrap();
    }
}

#[cfg(feature = "python")]
#[allow(missing_docs)]
#[allow(clippy::unnecessary_fallible_conversions)]
/// `InProcess` Python bindings
pub mod pybind {
    use alloc::boxed::Box;

    use libafl_bolts::tuples::tuple_list;
    use pyo3::{prelude::*, types::PyBytes};

    use crate::{
        events::pybind::PythonEventManager,
        executors::{inprocess::OwnedInProcessExecutor, pybind::PythonExecutor, ExitKind},
        fuzzer::pybind::PythonStdFuzzerWrapper,
        inputs::{BytesInput, HasBytesVec},
        observers::pybind::PythonObserversTuple,
        state::pybind::{PythonStdState, PythonStdStateWrapper},
    };

    #[pyclass(unsendable, name = "InProcessExecutor")]
    #[derive(Debug)]
    /// Python class for OwnedInProcessExecutor (i.e. InProcessExecutor with owned harness)
    pub struct PythonOwnedInProcessExecutor {
        /// Rust wrapped OwnedInProcessExecutor object
        pub inner: OwnedInProcessExecutor<PythonObserversTuple, PythonStdState>,
    }

    #[pymethods]
    impl PythonOwnedInProcessExecutor {
        #[new]
        fn new(
            harness: PyObject,
            py_observers: PythonObserversTuple,
            py_fuzzer: &mut PythonStdFuzzerWrapper,
            py_state: &mut PythonStdStateWrapper,
            py_event_manager: &mut PythonEventManager,
        ) -> Self {
            Self {
                inner: OwnedInProcessExecutor::generic(
                    tuple_list!(),
                    Box::new(move |input: &BytesInput| {
                        Python::with_gil(|py| -> PyResult<()> {
                            let args = (PyBytes::new(py, input.bytes()),);
                            harness.call1(py, args)?;
                            Ok(())
                        })
                        .unwrap();
                        ExitKind::Ok
                    }),
                    py_observers,
                    py_fuzzer.unwrap_mut(),
                    py_state.unwrap_mut(),
                    py_event_manager,
                )
                .expect("Failed to create the Executor"),
            }
        }

        #[must_use]
        pub fn as_executor(slf: Py<Self>) -> PythonExecutor {
            PythonExecutor::new_inprocess(slf)
        }
    }

    /// Register the classes to the python module
    pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
        m.add_class::<PythonOwnedInProcessExecutor>()?;
        Ok(())
    }
}
