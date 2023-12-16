use core::{
    ffi::c_void,
    ptr::{self, null_mut, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
};

use libafl_bolts::os::unix_signals::setup_signal_handler;

use crate::{
    events::{EventFirer, EventRestarter},
    executors::{
        inprocess::run_observers_and_save_state, Executor, ExecutorHooks, ExitKind, HasObservers,
    },
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::UsesInput,
    state::{HasCorpus, HasExecutions, HasSolutions},
    Error,
};

/// The inmem executor's handlers.
#[derive(Debug)]
pub struct DefaultExecutorHooks {
    /// On crash C function pointer
    #[cfg(any(unix, feature = "std"))]
    pub crash_handler: *const c_void,
    /// On timeout C function pointer
    #[cfg(any(unix, feature = "std"))]
    pub timeout_handler: *const c_void,
}

impl DefaultExecutorHooks {
    /// Create new [`InProcessHandlers`].
    #[cfg(not(all(windows, feature = "std")))]
    pub fn new<E, EM, OF, Z>() -> Result<Self, Error>
    where
        E: Executor<EM, Z> + HasObservers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        #[cfg(unix)]
        #[cfg_attr(miri, allow(unused_variables))]
        unsafe {
            let data = &mut GLOBAL_STATE;
            #[cfg(feature = "std")]
            unix_signal_handler::setup_panic_hook::<E, EM, OF, Z>();
            #[cfg(not(miri))]
            setup_signal_handler(data)?;
            compiler_fence(Ordering::SeqCst);
            Ok(Self {
                crash_handler: unix_signal_handler::inproc_crash_handler::<E, EM, OF, Z>
                    as *const c_void,
                timeout_handler: unix_signal_handler::inproc_timeout_handler::<E, EM, OF, Z>
                    as *const _,
            })
        }
        #[cfg(not(any(unix, feature = "std")))]
        Ok(Self {})
    }

    /// Create new [`InProcessHandlers`].
    #[cfg(all(windows, feature = "std"))]
    pub fn new<E, EM, OF, Z>() -> Result<Self, Error>
    where
        E: Executor<EM, Z> + HasObservers + HasInProcessHandlers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: State + HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        unsafe {
            let data = &mut GLOBAL_STATE;
            #[cfg(feature = "std")]
            windows_exception_handler::setup_panic_hook::<E, EM, OF, Z>();
            setup_exception_handler(data)?;
            compiler_fence(Ordering::SeqCst);

            Ok(Self {
                crash_handler: windows_exception_handler::inproc_crash_handler::<E, EM, OF, Z>
                    as *const _,
                timeout_handler: windows_exception_handler::inproc_timeout_handler::<E, EM, OF, Z>
                    as *const c_void,
            })
        }
    }

    /// Replace the handlers with `nop` handlers, deactivating the handlers
    #[must_use]
    pub fn nop() -> Self {
        let ret;
        #[cfg(any(unix, feature = "std"))]
        {
            ret = Self {
                crash_handler: ptr::null(),
                timeout_handler: ptr::null(),
            };
        }
        #[cfg(not(any(unix, feature = "std")))]
        {
            ret = Self {};
        }
        ret
    }
}

impl ExecutorHooks for DefaultExecutorHooks {
    /// Call before running a target.
    #[allow(clippy::unused_self)]
    fn pre_run_target<E, EM, I, S, Z>(
        &self,
        _executor: &E,
        _fuzzer: &mut Z,
        _state: &mut S,
        _mgr: &mut EM,
        _input: &I,
    ) {
        #[cfg(unix)]
        unsafe {
            let data = &mut GLOBAL_STATE;
            write_volatile(
                &mut data.current_input_ptr,
                _input as *const _ as *const c_void,
            );
            write_volatile(
                &mut data.executor_ptr,
                _executor as *const _ as *const c_void,
            );
            data.crash_handler = self.crash_handler;
            data.timeout_handler = self.timeout_handler;
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(&mut data.state_ptr, _state as *mut _ as *mut c_void);
            write_volatile(&mut data.event_mgr_ptr, _mgr as *mut _ as *mut c_void);
            write_volatile(&mut data.fuzzer_ptr, _fuzzer as *mut _ as *mut c_void);
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(all(windows, feature = "std"))]
        unsafe {
            let data = &mut GLOBAL_STATE;
            write_volatile(
                &mut data.current_input_ptr,
                _input as *const _ as *const c_void,
            );
            write_volatile(
                &mut data.executor_ptr,
                _executor as *const _ as *const c_void,
            );
            data.crash_handler = self.crash_handler;
            data.timeout_handler = self.timeout_handler;
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(&mut data.state_ptr, _state as *mut _ as *mut c_void);
            write_volatile(&mut data.event_mgr_ptr, _mgr as *mut _ as *mut c_void);
            write_volatile(&mut data.fuzzer_ptr, _fuzzer as *mut _ as *mut c_void);
            compiler_fence(Ordering::SeqCst);
        }
    }

    /// Call after running a target.
    #[allow(clippy::unused_self)]
    fn post_run_target(&self) {
        #[cfg(unix)]
        unsafe {
            write_volatile(&mut GLOBAL_STATE.current_input_ptr, ptr::null());
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(all(windows, feature = "std"))]
        unsafe {
            write_volatile(&mut GLOBAL_STATE.current_input_ptr, ptr::null());
            compiler_fence(Ordering::SeqCst);
        }
    }
}

/// The global state of the in-process harness.
#[derive(Debug)]
pub struct InProcessExecutorHandlerData {
    pub(crate) state_ptr: *mut c_void,
    pub(crate) event_mgr_ptr: *mut c_void,
    pub(crate) fuzzer_ptr: *mut c_void,
    pub(crate) executor_ptr: *const c_void,
    pub(crate) current_input_ptr: *const c_void,
    pub(crate) in_handler: bool,

    /// The timeout handler
    #[cfg(any(unix, feature = "std"))]
    pub(crate) crash_handler: *const c_void,
    /// The timeout handler
    #[cfg(any(unix, feature = "std"))]
    pub(crate) timeout_handler: *const c_void,

    #[cfg(all(windows, feature = "std"))]
    pub(crate) ptp_timer: Option<PTP_TIMER>,
    #[cfg(all(windows, feature = "std"))]
    pub(crate) in_target: u64,
    #[cfg(all(windows, feature = "std"))]
    pub(crate) critical: *mut c_void,
    #[cfg(all(windows, feature = "std"))]
    pub(crate) timeout_input_ptr: *mut c_void,

    #[cfg(any(unix, feature = "std"))]
    pub(crate) timeout_executor_ptr: *mut c_void,
}

unsafe impl Send for InProcessExecutorHandlerData {}
unsafe impl Sync for InProcessExecutorHandlerData {}

impl InProcessExecutorHandlerData {
    #[cfg(any(unix, feature = "std"))]
    fn executor_mut<'a, E>(&self) -> &'a mut E {
        unsafe { (self.executor_ptr as *mut E).as_mut().unwrap() }
    }

    #[cfg(any(unix, feature = "std"))]
    fn state_mut<'a, S>(&self) -> &'a mut S {
        unsafe { (self.state_ptr as *mut S).as_mut().unwrap() }
    }

    #[cfg(any(unix, feature = "std"))]
    fn event_mgr_mut<'a, EM>(&self) -> &'a mut EM {
        unsafe { (self.event_mgr_ptr as *mut EM).as_mut().unwrap() }
    }

    #[cfg(any(unix, feature = "std"))]
    fn fuzzer_mut<'a, Z>(&self) -> &'a mut Z {
        unsafe { (self.fuzzer_ptr as *mut Z).as_mut().unwrap() }
    }

    #[cfg(any(unix, feature = "std"))]
    fn take_current_input<'a, I>(&mut self) -> &'a I {
        let r = unsafe { (self.current_input_ptr as *const I).as_ref().unwrap() };
        self.current_input_ptr = ptr::null();
        r
    }

    #[cfg(any(unix, feature = "std"))]
    pub(crate) fn is_valid(&self) -> bool {
        !self.current_input_ptr.is_null()
    }

    #[cfg(any(unix, feature = "std"))]
    fn timeout_executor_mut<'a, E>(&self) -> &'a mut crate::executors::timeout::TimeoutExecutor<E> {
        unsafe {
            (self.timeout_executor_ptr as *mut crate::executors::timeout::TimeoutExecutor<E>)
                .as_mut()
                .unwrap()
        }
    }

    #[cfg(any(unix, feature = "std"))]
    fn set_in_handler(&mut self, v: bool) -> bool {
        let old = self.in_handler;
        self.in_handler = v;
        old
    }
}

/// Exception handling needs some nasty unsafe.
pub(crate) static mut GLOBAL_STATE: InProcessExecutorHandlerData = InProcessExecutorHandlerData {
    // The state ptr for signal handling
    state_ptr: null_mut(),
    // The event manager ptr for signal handling
    event_mgr_ptr: null_mut(),
    // The fuzzer ptr for signal handling
    fuzzer_ptr: null_mut(),
    // The executor ptr for signal handling
    executor_ptr: ptr::null(),
    // The current input for signal handling
    current_input_ptr: ptr::null(),

    in_handler: false,

    // The crash handler fn
    #[cfg(any(unix, feature = "std"))]
    crash_handler: ptr::null(),
    // The timeout handler fn
    #[cfg(any(unix, feature = "std"))]
    timeout_handler: ptr::null(),
    #[cfg(all(windows, feature = "std"))]
    ptp_timer: None,
    #[cfg(all(windows, feature = "std"))]
    in_target: 0,
    #[cfg(all(windows, feature = "std"))]
    critical: null_mut(),
    #[cfg(all(windows, feature = "std"))]
    timeout_input_ptr: null_mut(),

    #[cfg(any(unix, feature = "std"))]
    timeout_executor_ptr: null_mut(),
};

/// Get the inprocess [`crate::state::State`]
#[must_use]
pub fn inprocess_get_state<'a, S>() -> Option<&'a mut S> {
    unsafe { (GLOBAL_STATE.state_ptr as *mut S).as_mut() }
}

/// Get the [`crate::events::EventManager`]
#[must_use]
pub fn inprocess_get_event_manager<'a, EM>() -> Option<&'a mut EM> {
    unsafe { (GLOBAL_STATE.event_mgr_ptr as *mut EM).as_mut() }
}

/// Gets the inprocess [`crate::fuzzer::Fuzzer`]
#[must_use]
pub fn inprocess_get_fuzzer<'a, F>() -> Option<&'a mut F> {
    unsafe { (GLOBAL_STATE.fuzzer_ptr as *mut F).as_mut() }
}

/// Gets the inprocess [`Executor`]
#[must_use]
pub fn inprocess_get_executor<'a, E>() -> Option<&'a mut E> {
    unsafe { (GLOBAL_STATE.executor_ptr as *mut E).as_mut() }
}

/// Gets the inprocess input
#[must_use]
pub fn inprocess_get_input<'a, I>() -> Option<&'a I> {
    unsafe { (GLOBAL_STATE.current_input_ptr as *const I).as_ref() }
}

/// Know if we ar eexecuting in a crash/timeout handler
#[must_use]
pub fn inprocess_in_handler() -> bool {
    unsafe { GLOBAL_STATE.in_handler }
}

// TODO remove this after executor refactor and libafl qemu new executor
/// Expose a version of the crash handler that can be called from e.g. an emulator
#[cfg(any(unix, feature = "std"))]
pub fn generic_inproc_crash_handler<E, EM, OF, Z>()
where
    E: Executor<EM, Z> + HasObservers,
    EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
    OF: Feedback<E::State>,
    E::State: HasExecutions + HasSolutions + HasCorpus,
    Z: HasObjective<Objective = OF, State = E::State>,
{
    let data = unsafe { &mut GLOBAL_STATE };
    let in_handler = data.set_in_handler(true);

    if data.is_valid() {
        let executor = data.executor_mut::<E>();
        // disarms timeout in case of TimeoutExecutor
        executor.post_run_reset();
        let state = data.state_mut::<E::State>();
        let event_mgr = data.event_mgr_mut::<EM>();
        let fuzzer = data.fuzzer_mut::<Z>();
        let input = data.take_current_input::<<E::State as UsesInput>::Input>();

        run_observers_and_save_state::<E, EM, OF, Z>(
            executor,
            state,
            input,
            fuzzer,
            event_mgr,
            ExitKind::Crash,
        );
    }

    data.set_in_handler(in_handler);
}

/// The inprocess executor singal handling code for unix
#[cfg(unix)]
pub mod unix_signal_handler {
    use alloc::vec::Vec;
    #[cfg(feature = "std")]
    use alloc::{boxed::Box, string::String};
    use core::mem::transmute;
    #[cfg(feature = "std")]
    use std::{io::Write, panic};

    use libafl_bolts::os::unix_signals::{ucontext_t, Handler, Signal};
    use libc::siginfo_t;

    #[cfg(feature = "std")]
    use crate::inputs::Input;
    use crate::{
        events::{EventFirer, EventRestarter},
        executors::{
            inprocess::run_observers_and_save_state,
            inprocess_hooks_unix::{InProcessExecutorHandlerData, GLOBAL_STATE},
            Executor, ExitKind, HasObservers,
        },
        feedbacks::Feedback,
        fuzzer::HasObjective,
        inputs::UsesInput,
        state::{HasCorpus, HasExecutions, HasSolutions},
    };

    pub(crate) type HandlerFuncPtr = unsafe fn(
        Signal,
        &mut siginfo_t,
        Option<&mut ucontext_t>,
        data: &mut InProcessExecutorHandlerData,
    );

    /// A handler that does nothing.
    /*pub fn nop_handler(
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
        _data: &mut InProcessExecutorHandlerData,
    ) {
    }*/

    #[cfg(unix)]
    impl Handler for InProcessExecutorHandlerData {
        fn handle(
            &mut self,
            signal: Signal,
            info: &mut siginfo_t,
            context: Option<&mut ucontext_t>,
        ) {
            unsafe {
                let data = &mut GLOBAL_STATE;
                let in_handler = data.set_in_handler(true);
                match signal {
                    Signal::SigUser2 | Signal::SigAlarm => {
                        if !data.timeout_handler.is_null() {
                            let func: HandlerFuncPtr = transmute(data.timeout_handler);
                            (func)(signal, info, context, data);
                        }
                    }
                    _ => {
                        if !data.crash_handler.is_null() {
                            let func: HandlerFuncPtr = transmute(data.crash_handler);
                            (func)(signal, info, context, data);
                        }
                    }
                }
                data.set_in_handler(in_handler);
            }
        }

        fn signals(&self) -> Vec<Signal> {
            vec![
                Signal::SigAlarm,
                Signal::SigUser2,
                Signal::SigAbort,
                Signal::SigBus,
                Signal::SigPipe,
                Signal::SigFloatingPointException,
                Signal::SigIllegalInstruction,
                Signal::SigSegmentationFault,
                Signal::SigTrap,
            ]
        }
    }

    /// invokes the `post_exec` hook on all observer in case of panic
    #[cfg(feature = "std")]
    pub fn setup_panic_hook<E, EM, OF, Z>()
    where
        E: HasObservers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        let old_hook = panic::take_hook();
        panic::set_hook(Box::new(move |panic_info| {
            old_hook(panic_info);
            let data = unsafe { &mut GLOBAL_STATE };
            let in_handler = data.set_in_handler(true);
            if data.is_valid() {
                // We are fuzzing!
                let executor = data.executor_mut::<E>();
                let state = data.state_mut::<E::State>();
                let input = data.take_current_input::<<E::State as UsesInput>::Input>();
                let fuzzer = data.fuzzer_mut::<Z>();
                let event_mgr = data.event_mgr_mut::<EM>();

                run_observers_and_save_state::<E, EM, OF, Z>(
                    executor,
                    state,
                    input,
                    fuzzer,
                    event_mgr,
                    ExitKind::Crash,
                );

                unsafe {
                    libc::_exit(128 + 6);
                } // SIGABRT exit code
            }
            data.set_in_handler(in_handler);
        }));
    }

    /// Timeout-Handler for in-process fuzzing.
    /// It will store the current State to shmem, then exit.
    ///
    /// # Safety
    /// Well, signal handling is not safe
    #[cfg(unix)]
    pub unsafe fn inproc_timeout_handler<E, EM, OF, Z>(
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
        data: &mut InProcessExecutorHandlerData,
    ) where
        E: HasObservers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        if !data.timeout_executor_ptr.is_null()
            && data.timeout_executor_mut::<E>().handle_timeout(data)
        {
            return;
        }

        if !data.is_valid() {
            log::warn!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing.");
            return;
        }

        let executor = data.executor_mut::<E>();
        let state = data.state_mut::<E::State>();
        let event_mgr = data.event_mgr_mut::<EM>();
        let fuzzer = data.fuzzer_mut::<Z>();
        let input = data.take_current_input::<<E::State as UsesInput>::Input>();

        log::error!("Timeout in fuzz run.");

        run_observers_and_save_state::<E, EM, OF, Z>(
            executor,
            state,
            input,
            fuzzer,
            event_mgr,
            ExitKind::Timeout,
        );

        libc::_exit(55);
    }

    /// Crash-Handler for in-process fuzzing.
    /// Will be used for signal handling.
    /// It will store the current State to shmem, then exit.
    ///
    /// # Safety
    /// Well, signal handling is not safe
    #[allow(clippy::too_many_lines)]
    pub unsafe fn inproc_crash_handler<E, EM, OF, Z>(
        signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
        data: &mut InProcessExecutorHandlerData,
    ) where
        E: Executor<EM, Z> + HasObservers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        #[cfg(all(target_os = "android", target_arch = "aarch64"))]
        let _context = _context.map(|p| {
            &mut *(((p as *mut _ as *mut libc::c_void as usize) + 128) as *mut libc::c_void
                as *mut ucontext_t)
        });

        log::error!("Crashed with {signal}");
        if data.is_valid() {
            let executor = data.executor_mut::<E>();
            // disarms timeout in case of TimeoutExecutor
            executor.post_run_reset();
            let state = data.state_mut::<E::State>();
            let event_mgr = data.event_mgr_mut::<EM>();
            let fuzzer = data.fuzzer_mut::<Z>();
            let input = data.take_current_input::<<E::State as UsesInput>::Input>();

            log::error!("Child crashed!");

            #[cfg(all(feature = "std", unix))]
            {
                let mut bsod = Vec::new();
                {
                    let mut writer = std::io::BufWriter::new(&mut bsod);
                    writeln!(writer, "input: {:?}", input.generate_name(0)).unwrap();
                    libafl_bolts::minibsod::generate_minibsod(
                        &mut writer,
                        signal,
                        _info,
                        _context.as_deref(),
                    )
                    .unwrap();
                    writer.flush().unwrap();
                }
                log::error!("{}", std::str::from_utf8(&bsod).unwrap());
            }

            run_observers_and_save_state::<E, EM, OF, Z>(
                executor,
                state,
                input,
                fuzzer,
                event_mgr,
                ExitKind::Crash,
            );
        } else {
            {
                log::error!("Double crash\n");
                #[cfg(target_os = "android")]
                let si_addr = (_info._pad[0] as i64) | ((_info._pad[1] as i64) << 32);
                #[cfg(not(target_os = "android"))]
                let si_addr = { _info.si_addr() as usize };

                log::error!(
                    "We crashed at addr 0x{si_addr:x}, but are not in the target... Bug in the fuzzer? Exiting."
                );

                #[cfg(all(feature = "std", unix))]
                {
                    let mut bsod = Vec::new();
                    {
                        let mut writer = std::io::BufWriter::new(&mut bsod);
                        libafl_bolts::minibsod::generate_minibsod(
                            &mut writer,
                            signal,
                            _info,
                            _context.as_deref(),
                        )
                        .unwrap();
                        writer.flush().unwrap();
                    }
                    log::error!("{}", std::str::from_utf8(&bsod).unwrap());
                }
            }

            #[cfg(feature = "std")]
            {
                log::error!("Type QUIT to restart the child");
                let mut line = String::new();
                while line.trim() != "QUIT" {
                    std::io::stdin().read_line(&mut line).unwrap();
                }
            }

            // TODO tell the parent to not restart
        }

        libc::_exit(128 + (signal as i32));
    }
}
