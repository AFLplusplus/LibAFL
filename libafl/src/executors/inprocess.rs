//! The [`InProcessExecutor`] is a libfuzzer-like executor, that will simply call a function.
//! It should usually be paired with extra error-handling, such as a restarting event manager, to be effective.
//!
//! Needs the `fork` feature flag.
#![allow(clippy::needless_pass_by_value)]

use alloc::boxed::Box;
#[cfg(all(feature = "std", unix, target_os = "linux"))]
use core::ptr::addr_of_mut;
#[cfg(all(unix, feature = "std"))]
use core::time::Duration;
use core::{
    borrow::BorrowMut,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ptr::null_mut,
};

#[cfg(all(feature = "std", unix))]
use libafl_bolts::os::unix_signals::Signal;
#[cfg(all(feature = "std", unix))]
use libafl_bolts::shmem::ShMemProvider;
#[cfg(all(feature = "std", unix))]
use nix::{
    sys::wait::{waitpid, WaitStatus},
    unistd::{fork, ForkResult},
};
#[cfg(windows)]
use windows::Win32::System::Threading::SetThreadStackGuarantee;

#[cfg(windows)]
use crate::executors::inprocess_hooks_win::DefaultExecutorHooks;
#[cfg(unix)]
use crate::executors::{
    inprocess_fork_hooks_unix::InChildDefaultExecutorHooks,
    inprocess_hooks_unix::DefaultExecutorHooks,
};
use crate::{
    corpus::{Corpus, Testcase},
    events::{Event, EventFirer, EventRestarter},
    executors::{Executor, ExecutorHooks, ExitKind, HasObservers},
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    observers::{ObserversTuple, UsesObservers},
    state::{HasCorpus, HasExecutions, HasMetadata, HasSolutions, State, UsesState},
    Error,
};

/// The process executor simply calls a target function, as mutable reference to a closure
pub type InProcessExecutor<'a, H, OT, S> = GenericInProcessExecutor<H, &'a mut H, OT, S>;

/// The process executor simply calls a target function, as boxed `FnMut` trait object
pub type OwnedInProcessExecutor<OT, S> = GenericInProcessExecutor<
    dyn FnMut(&<S as UsesInput>::Input) -> ExitKind,
    Box<dyn FnMut(&<S as UsesInput>::Input) -> ExitKind>,
    OT,
    S,
>;

/// The inmem executor simply calls a target function, then returns afterwards.
#[allow(dead_code)]
pub struct GenericInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: State,
{
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: HB,
    /// The observers, observing each run
    observers: OT,
    // Crash and timeout hah
    default_hooks: DefaultExecutorHooks,
    phantom: PhantomData<(S, *const H)>,
}

impl<H, HB, OT, S> Debug for GenericInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
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

impl<H, HB, OT, S> UsesState for GenericInProcessExecutor<H, HB, OT, S>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: State,
{
    type State = S;
}

impl<H, HB, OT, S> UsesObservers for GenericInProcessExecutor<H, HB, OT, S>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: State,
{
    type Observers = OT;
}

impl<EM, H, HB, OT, S, Z> Executor<EM, Z> for GenericInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    EM: UsesState<State = S>,
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
        self.default_hooks
            .pre_run_target(self, fuzzer, state, mgr, input);

        let ret = (self.harness_fn.borrow_mut())(input);

        self.default_hooks.post_run_target();
        Ok(ret)
    }
}

impl<H, HB, OT, S> HasObservers for GenericInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
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

impl<H, HB, OT, S> GenericInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&<S as UsesInput>::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: HasExecutions + HasSolutions + HasCorpus + State,
{
    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `harness_fn` - the harness, executing the function
    /// * `observers` - the observers observing the target during execution
    /// This may return an error on unix, if signal handler setup fails
    pub fn new<EM, OF, Z>(
        harness_fn: HB,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        Self: Executor<EM, Z, State = S>,
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: State,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let default_hooks = DefaultExecutorHooks::new::<Self, EM, OF, Z>()?;
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
        Ok(Self {
            harness_fn,
            observers,
            default_hooks,
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

    /// The default hooks
    #[inline]
    pub fn default_hooks(&self) -> &DefaultExecutorHooks {
        &self.default_hooks
    }

    /// The default hooks (mutable)
    #[inline]
    pub fn default_hooks_mut(&mut self) -> &mut DefaultExecutorHooks {
        &mut self.default_hooks
    }
}

/// The struct has [`InProcessHandlers`].
#[cfg(windows)]
pub trait HasDefaultExecutorHooks {
    /// Get the in-process handlers.
    fn inprocess_handlers(&self) -> &DefaultExecutorHooks;
}

#[cfg(windows)]
impl<H, HB, OT, S> HasDefaultExecutorHooks for GenericInProcessExecutor<H, HB, OT, S>
where
    H: FnMut(&<S as UsesInput>::Input) -> ExitKind + ?Sized,
    HB: BorrowMut<H>,
    OT: ObserversTuple<S>,
    S: State + HasExecutions + HasSolutions + HasCorpus,
{
    /// the timeout handler
    #[inline]
    fn inprocess_handlers(&self) -> &DefaultExecutorHooks {
        &self.handlers
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

#[repr(C)]
#[cfg(all(feature = "std", unix, not(target_os = "linux")))]
struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[cfg(all(feature = "std", unix, not(target_os = "linux")))]
impl Debug for Timeval {
    #[allow(clippy::cast_sign_loss)]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Timeval {{ tv_sec: {:?}, tv_usec: {:?} (tv: {:?}) }}",
            self.tv_sec,
            self.tv_usec,
            Duration::new(self.tv_sec as _, (self.tv_usec * 1000) as _)
        )
    }
}

#[repr(C)]
#[cfg(all(feature = "std", unix, not(target_os = "linux")))]
#[derive(Debug)]
struct Itimerval {
    pub it_interval: Timeval,
    pub it_value: Timeval,
}

#[cfg(all(feature = "std", unix, not(target_os = "linux")))]
extern "C" {
    fn setitimer(
        which: libc::c_int,
        new_value: *mut Itimerval,
        old_value: *mut Itimerval,
    ) -> libc::c_int;
}

#[cfg(all(feature = "std", unix, not(target_os = "linux")))]
const ITIMER_REAL: libc::c_int = 0;

/// [`InProcessForkExecutor`] is an executor that forks the current process before each execution.
#[cfg(all(feature = "std", unix))]
pub struct InProcessForkExecutor<'a, H, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: UsesInput,
    SP: ShMemProvider,
{
    harness_fn: &'a mut H,
    shmem_provider: SP,
    observers: OT,
    handlers: InChildDefaultExecutorHooks,
    phantom: PhantomData<S>,
}

/// Timeout executor for [`InProcessForkExecutor`]
#[cfg(all(feature = "std", unix))]
pub struct TimeoutInProcessForkExecutor<'a, H, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: UsesInput,
    SP: ShMemProvider,
{
    harness_fn: &'a mut H,
    shmem_provider: SP,
    observers: OT,
    handlers: InChildDefaultExecutorHooks,
    #[cfg(target_os = "linux")]
    itimerspec: libc::itimerspec,
    #[cfg(all(unix, not(target_os = "linux")))]
    itimerval: Itimerval,
    phantom: PhantomData<S>,
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, OT, S, SP> Debug for InProcessForkExecutor<'a, H, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S> + Debug,
    S: UsesInput,
    SP: ShMemProvider,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("InProcessForkExecutor")
            .field("observers", &self.observers)
            .field("shmem_provider", &self.shmem_provider)
            .finish()
    }
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, OT, S, SP> Debug for TimeoutInProcessForkExecutor<'a, H, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S> + Debug,
    S: UsesInput,
    SP: ShMemProvider,
{
    #[cfg(target_os = "linux")]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeoutInProcessForkExecutor")
            .field("observers", &self.observers)
            .field("shmem_provider", &self.shmem_provider)
            .field("itimerspec", &self.itimerspec)
            .finish()
    }

    #[cfg(not(target_os = "linux"))]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[cfg(not(target_os = "linux"))]
        return f
            .debug_struct("TimeoutInProcessForkExecutor")
            .field("observers", &self.observers)
            .field("shmem_provider", &self.shmem_provider)
            .field("itimerval", &self.itimerval)
            .finish();
    }
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, OT, S, SP> UsesState for InProcessForkExecutor<'a, H, OT, S, SP>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
{
    type State = S;
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, OT, S, SP> UsesState for TimeoutInProcessForkExecutor<'a, H, OT, S, SP>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
{
    type State = S;
}

#[cfg(all(feature = "std", unix))]
impl<'a, EM, H, OT, S, SP, Z> Executor<EM, Z> for InProcessForkExecutor<'a, H, OT, S, SP>
where
    EM: UsesState<State = S>,
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: State + HasExecutions,
    SP: ShMemProvider,
    Z: UsesState<State = S>,
{
    #[allow(unreachable_code)]
    #[inline]
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;
        unsafe {
            self.shmem_provider.pre_fork()?;
            match fork() {
                Ok(ForkResult::Child) => {
                    // Child
                    self.shmem_provider.post_fork(true)?;

                    self.handlers.pre_run_target(self, state, input);

                    self.observers
                        .pre_exec_child_all(state, input)
                        .expect("Failed to run pre_exec on observers");

                    (self.harness_fn)(input);

                    self.observers
                        .post_exec_child_all(state, input, &ExitKind::Ok)
                        .expect("Failed to run post_exec on observers");

                    libc::_exit(0);

                    Ok(ExitKind::Ok)
                }
                Ok(ForkResult::Parent { child }) => {
                    // Parent
                    // log::info!("from parent {} child is {}", std::process::id(), child);
                    self.shmem_provider.post_fork(false)?;

                    let res = waitpid(child, None)?;

                    match res {
                        WaitStatus::Signaled(_, _, _) => Ok(ExitKind::Crash),
                        WaitStatus::Exited(_, code) => {
                            if code > 128 && code < 160 {
                                // Signal exit codes
                                Ok(ExitKind::Crash)
                            } else {
                                Ok(ExitKind::Ok)
                            }
                        }
                        _ => Ok(ExitKind::Ok),
                    }
                }
                Err(e) => Err(Error::from(e)),
            }
        }
    }
}

#[cfg(all(feature = "std", unix))]
impl<'a, EM, H, OT, S, SP, Z> Executor<EM, Z> for TimeoutInProcessForkExecutor<'a, H, OT, S, SP>
where
    EM: UsesState<State = S>,
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: State + HasExecutions,
    SP: ShMemProvider,
    Z: UsesState<State = S>,
{
    #[allow(unreachable_code)]
    #[inline]
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        unsafe {
            self.shmem_provider.pre_fork()?;
            match fork() {
                Ok(ForkResult::Child) => {
                    // Child
                    self.shmem_provider.post_fork(true)?;

                    self.handlers.pre_run_target(self, state, input);

                    self.observers
                        .pre_exec_child_all(state, input)
                        .expect("Failed to run post_exec on observers");

                    #[cfg(target_os = "linux")]
                    {
                        let mut timerid: libc::timer_t = null_mut();
                        // creates a new per-process interval timer
                        // we can't do this from the parent, timerid is unique to each process.
                        libc::timer_create(
                            libc::CLOCK_MONOTONIC,
                            null_mut(),
                            addr_of_mut!(timerid),
                        );

                        // log::info!("Set timer! {:#?} {timerid:#?}", self.itimerspec);
                        let _: i32 = libc::timer_settime(
                            timerid,
                            0,
                            addr_of_mut!(self.itimerspec),
                            null_mut(),
                        );
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        setitimer(ITIMER_REAL, &mut self.itimerval, null_mut());
                    }
                    // log::trace!("{v:#?} {}", nix::errno::errno());
                    (self.harness_fn)(input);

                    self.observers
                        .post_exec_child_all(state, input, &ExitKind::Ok)
                        .expect("Failed to run post_exec on observers");

                    libc::_exit(0);

                    Ok(ExitKind::Ok)
                }
                Ok(ForkResult::Parent { child }) => {
                    // Parent
                    // log::trace!("from parent {} child is {}", std::process::id(), child);
                    self.shmem_provider.post_fork(false)?;

                    let res = waitpid(child, None)?;
                    log::trace!("{res:#?}");
                    match res {
                        WaitStatus::Signaled(_, signal, _) => match signal {
                            nix::sys::signal::Signal::SIGALRM
                            | nix::sys::signal::Signal::SIGUSR2 => Ok(ExitKind::Timeout),
                            _ => Ok(ExitKind::Crash),
                        },
                        WaitStatus::Exited(_, code) => {
                            if code > 128 && code < 160 {
                                // Signal exit codes
                                let signal = code - 128;
                                if signal == Signal::SigAlarm as libc::c_int
                                    || signal == Signal::SigUser2 as libc::c_int
                                {
                                    Ok(ExitKind::Timeout)
                                } else {
                                    Ok(ExitKind::Crash)
                                }
                            } else {
                                Ok(ExitKind::Ok)
                            }
                        }
                        _ => Ok(ExitKind::Ok),
                    }
                }
                Err(e) => Err(Error::from(e)),
            }
        }
    }
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, OT, S, SP> InProcessForkExecutor<'a, H, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
{
    /// Creates a new [`InProcessForkExecutor`]
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        shmem_provider: SP,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter,
        OF: Feedback<S>,
        S: HasSolutions,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let handlers = InChildDefaultExecutorHooks::new::<Self>()?;
        Ok(Self {
            harness_fn,
            shmem_provider,
            observers,
            handlers,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> &H {
        self.harness_fn
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness_fn
    }
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, OT, S, SP> TimeoutInProcessForkExecutor<'a, H, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
{
    /// Creates a new [`TimeoutInProcessForkExecutor`]
    #[cfg(target_os = "linux")]
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
        shmem_provider: SP,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        S: HasSolutions,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let handlers = InChildDefaultExecutorHooks::with_timeout::<Self>()?;
        let milli_sec = timeout.as_millis();
        let it_value = libc::timespec {
            tv_sec: (milli_sec / 1000) as _,
            tv_nsec: ((milli_sec % 1000) * 1000 * 1000) as _,
        };
        let it_interval = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let itimerspec = libc::itimerspec {
            it_interval,
            it_value,
        };

        Ok(Self {
            harness_fn,
            shmem_provider,
            observers,
            handlers,
            itimerspec,
            phantom: PhantomData,
        })
    }

    /// Creates a new [`TimeoutInProcessForkExecutor`], non linux
    #[cfg(not(target_os = "linux"))]
    pub fn new<EM, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
        timeout: Duration,
        shmem_provider: SP,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<State = S> + EventRestarter<State = S>,
        OF: Feedback<S>,
        S: HasSolutions,
        Z: HasObjective<Objective = OF, State = S>,
    {
        let handlers = InChildDefaultExecutorHooks::with_timeout::<Self>()?;
        let milli_sec = timeout.as_millis();
        let it_value = Timeval {
            tv_sec: (milli_sec / 1000) as i64,
            tv_usec: (milli_sec % 1000) as i64,
        };
        let it_interval = Timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let itimerval = Itimerval {
            it_interval,
            it_value,
        };

        Ok(Self {
            harness_fn,
            shmem_provider,
            observers,
            handlers,
            itimerval,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> &H {
        self.harness_fn
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness_fn
    }
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, OT, S, SP> UsesObservers for InProcessForkExecutor<'a, H, OT, S, SP>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
{
    type Observers = OT;
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, OT, S, SP> UsesObservers for TimeoutInProcessForkExecutor<'a, H, OT, S, SP>
where
    H: ?Sized + FnMut(&S::Input) -> ExitKind,
    OT: ObserversTuple<S>,
    S: State,
    SP: ShMemProvider,
{
    type Observers = OT;
}

#[cfg(all(feature = "std", unix))]
impl<'a, H, OT, S, SP> HasObservers for InProcessForkExecutor<'a, H, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
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

#[cfg(all(feature = "std", unix))]
impl<'a, H, OT, S, SP> HasObservers for TimeoutInProcessForkExecutor<'a, H, OT, S, SP>
where
    H: FnMut(&S::Input) -> ExitKind + ?Sized,
    S: State,
    OT: ObserversTuple<S>,
    SP: ShMemProvider,
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

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use libafl_bolts::tuples::tuple_list;
    #[cfg(all(feature = "std", feature = "fork", unix))]
    use serial_test::serial;

    #[cfg(unix)]
    use crate::executors::inprocess_hooks_unix::DefaultExecutorHooks;
    #[cfg(windows)]
    use crate::executors::inprocess_hooks_win::DefaultExecutorHooks;
    use crate::{
        events::NopEventManager,
        executors::{Executor, ExitKind, InProcessExecutor},
        inputs::{NopInput, UsesInput},
        state::NopState,
        NopFuzzer,
    };

    impl UsesInput for () {
        type Input = NopInput;
    }

    #[test]
    fn test_inmem_exec() {
        let mut harness = |_buf: &NopInput| ExitKind::Ok;

        let mut in_process_executor = InProcessExecutor::<_, _, _> {
            harness_fn: &mut harness,
            observers: tuple_list!(),
            default_hooks: DefaultExecutorHooks::nop(),
            phantom: PhantomData,
        };
        let input = NopInput {};
        in_process_executor
            .run_target(
                &mut NopFuzzer::new(),
                &mut NopState::new(),
                &mut NopEventManager::new(),
                &input,
            )
            .unwrap();
    }

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    #[cfg(all(feature = "std", feature = "fork", unix))]
    fn test_inprocessfork_exec() {
        use libafl_bolts::shmem::{ShMemProvider, StdShMemProvider};

        use crate::{
            events::SimpleEventManager,
            executors::{inprocess::InChildDefaultExecutorHooks, InProcessForkExecutor},
            state::NopState,
            NopFuzzer,
        };

        let provider = StdShMemProvider::new().unwrap();

        let mut harness = |_buf: &NopInput| ExitKind::Ok;
        let mut in_process_fork_executor = InProcessForkExecutor::<_, (), _, _> {
            harness_fn: &mut harness,
            shmem_provider: provider,
            observers: tuple_list!(),
            handlers: InChildDefaultExecutorHooks::nop(),
            phantom: PhantomData,
        };
        let input = NopInput {};
        let mut fuzzer = NopFuzzer::new();
        let mut state = NopState::new();
        let mut mgr = SimpleEventManager::printing();
        in_process_fork_executor
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
                inner: OwnedInProcessExecutor::new(
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
