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

/// Same as `inproc_crash_handler`, but this is called when address sanitizer exits, not from the exception handler
#[cfg(all(windows, feature = "std"))]
pub mod windows_asan_handler {
    use alloc::string::String;
    use core::sync::atomic::{compiler_fence, Ordering};

    use windows::Win32::System::Threading::{
        EnterCriticalSection, LeaveCriticalSection, CRITICAL_SECTION,
    };

    use crate::{
        events::{EventFirer, EventRestarter},
        executors::{
            inprocess::{run_observers_and_save_state, GLOBAL_STATE},
            Executor, ExitKind, HasObservers,
        },
        feedbacks::Feedback,
        fuzzer::HasObjective,
        inputs::UsesInput,
        state::{HasCorpus, HasExecutions, HasSolutions},
    };

    /// # Safety
    /// ASAN deatch handler
    pub unsafe extern "C" fn asan_death_handler<E, EM, OF, Z>()
    where
        E: Executor<EM, Z> + HasObservers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        let data = &mut GLOBAL_STATE;
        data.set_in_handler(true);
        // Have we set a timer_before?
        if data.ptp_timer.is_some() {
            /*
                We want to prevent the timeout handler being run while the main thread is executing the crash handler
                Timeout handler runs if it has access to the critical section or data.in_target == 0
                Writing 0 to the data.in_target makes the timeout handler makes the timeout handler invalid.
            */
            compiler_fence(Ordering::SeqCst);
            EnterCriticalSection(data.critical as *mut CRITICAL_SECTION);
            compiler_fence(Ordering::SeqCst);
            data.in_target = 0;
            compiler_fence(Ordering::SeqCst);
            LeaveCriticalSection(data.critical as *mut CRITICAL_SECTION);
            compiler_fence(Ordering::SeqCst);
        }

        log::error!("ASAN detected crash!");
        if data.current_input_ptr.is_null() {
            {
                log::error!("Double crash\n");
                log::error!(
                "ASAN detected crash but we're not in the target... Bug in the fuzzer? Exiting.",
                );
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
        } else {
            let executor = data.executor_mut::<E>();
            // reset timer
            if data.ptp_timer.is_some() {
                executor.post_run_reset();
                data.ptp_timer = None;
            }

            let state = data.state_mut::<E::State>();
            let fuzzer = data.fuzzer_mut::<Z>();
            let event_mgr = data.event_mgr_mut::<EM>();

            log::error!("Child crashed!");

            // Make sure we don't crash in the crash handler forever.
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
        // Don't need to exit, Asan will exit for us
        // ExitProcess(1);
    }
}

#[cfg(all(windows, feature = "std"))]
pub mod windows_exception_handler {
    #[cfg(feature = "std")]
    use alloc::boxed::Box;
    use alloc::{string::String, vec::Vec};
    use core::{
        ffi::c_void,
        mem::transmute,
        ptr,
        sync::atomic::{compiler_fence, Ordering},
    };
    #[cfg(feature = "std")]
    use std::panic;

    use libafl_bolts::os::windows_exceptions::{
        ExceptionCode, Handler, CRASH_EXCEPTIONS, EXCEPTION_HANDLERS_SIZE, EXCEPTION_POINTERS,
    };
    use windows::Win32::System::Threading::{
        EnterCriticalSection, ExitProcess, LeaveCriticalSection, CRITICAL_SECTION,
    };

    use crate::{
        events::{EventFirer, EventRestarter},
        executors::{
            inprocess::{
                run_observers_and_save_state, HasInProcessHandlers, InProcessExecutorHandlerData,
                GLOBAL_STATE,
            },
            Executor, ExitKind, HasObservers,
        },
        feedbacks::Feedback,
        fuzzer::HasObjective,
        inputs::UsesInput,
        state::{HasCorpus, HasExecutions, HasSolutions, State},
    };

    pub(crate) type HandlerFuncPtr =
        unsafe fn(*mut EXCEPTION_POINTERS, &mut InProcessExecutorHandlerData);

    /*pub unsafe fn nop_handler(
        _code: ExceptionCode,
        _exception_pointers: *mut EXCEPTION_POINTERS,
        _data: &mut InProcessExecutorHandlerData,
    ) {
    }*/

    impl Handler for InProcessExecutorHandlerData {
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        fn handle(&mut self, _code: ExceptionCode, exception_pointers: *mut EXCEPTION_POINTERS) {
            unsafe {
                let data = &mut GLOBAL_STATE;
                let in_handler = data.set_in_handler(true);
                if !data.crash_handler.is_null() {
                    let func: HandlerFuncPtr = transmute(data.crash_handler);
                    (func)(exception_pointers, data);
                }
                data.set_in_handler(in_handler);
            }
        }

        fn exceptions(&self) -> Vec<ExceptionCode> {
            let crash_list = CRASH_EXCEPTIONS.to_vec();
            assert!(crash_list.len() < EXCEPTION_HANDLERS_SIZE - 1);
            crash_list
        }
    }

    /// invokes the `post_exec` hook on all observer in case of panic
    ///
    /// # Safety
    /// Well, exception handling is not safe
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
            let data = unsafe { &mut GLOBAL_STATE };
            let in_handler = data.set_in_handler(true);
            // Have we set a timer_before?
            unsafe {
                if data.ptp_timer.is_some() {
                    /*
                        We want to prevent the timeout handler being run while the main thread is executing the crash handler
                        Timeout handler runs if it has access to the critical section or data.in_target == 0
                        Writing 0 to the data.in_target makes the timeout handler makes the timeout handler invalid.
                    */
                    compiler_fence(Ordering::SeqCst);
                    EnterCriticalSection(data.critical as *mut CRITICAL_SECTION);
                    compiler_fence(Ordering::SeqCst);
                    data.in_target = 0;
                    compiler_fence(Ordering::SeqCst);
                    LeaveCriticalSection(data.critical as *mut CRITICAL_SECTION);
                    compiler_fence(Ordering::SeqCst);
                }
            }

            if data.is_valid() {
                // We are fuzzing!
                let executor = data.executor_mut::<E>();
                let state = data.state_mut::<E::State>();
                let fuzzer = data.fuzzer_mut::<Z>();
                let event_mgr = data.event_mgr_mut::<EM>();

                let input = data.take_current_input::<<E::State as UsesInput>::Input>();

                run_observers_and_save_state::<E, EM, OF, Z>(
                    executor,
                    state,
                    input,
                    fuzzer,
                    event_mgr,
                    ExitKind::Crash,
                );

                unsafe {
                    ExitProcess(1);
                }
            }
            old_hook(panic_info);
            data.set_in_handler(in_handler);
        }));
    }

    /// Timeout handler for windows
    ///
    /// # Safety
    /// Well, exception handling is not safe
    pub unsafe extern "system" fn inproc_timeout_handler<E, EM, OF, Z>(
        _p0: *mut u8,
        global_state: *mut c_void,
        _p1: *mut u8,
    ) where
        E: HasObservers + HasInProcessHandlers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: State + HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        let data: &mut InProcessExecutorHandlerData =
            &mut *(global_state as *mut InProcessExecutorHandlerData);
        compiler_fence(Ordering::SeqCst);
        EnterCriticalSection((data.critical as *mut CRITICAL_SECTION).as_mut().unwrap());
        compiler_fence(Ordering::SeqCst);

        if !data.timeout_executor_ptr.is_null()
            && data.timeout_executor_mut::<E>().handle_timeout(data)
        {
            compiler_fence(Ordering::SeqCst);
            LeaveCriticalSection((data.critical as *mut CRITICAL_SECTION).as_mut().unwrap());
            compiler_fence(Ordering::SeqCst);

            return;
        }

        if data.in_target == 1 {
            let executor = data.executor_mut::<E>();
            let state = data.state_mut::<E::State>();
            let fuzzer = data.fuzzer_mut::<Z>();
            let event_mgr = data.event_mgr_mut::<EM>();

            if data.timeout_input_ptr.is_null() {
                log::error!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing. Exiting");
            } else {
                log::error!("Timeout in fuzz run.");

                let input = (data.timeout_input_ptr as *const <E::State as UsesInput>::Input)
                    .as_ref()
                    .unwrap();
                data.timeout_input_ptr = ptr::null_mut();

                run_observers_and_save_state::<E, EM, OF, Z>(
                    executor,
                    state,
                    input,
                    fuzzer,
                    event_mgr,
                    ExitKind::Timeout,
                );

                compiler_fence(Ordering::SeqCst);

                ExitProcess(1);
            }
        }
        compiler_fence(Ordering::SeqCst);
        LeaveCriticalSection((data.critical as *mut CRITICAL_SECTION).as_mut().unwrap());
        compiler_fence(Ordering::SeqCst);
        // log::info!("TIMER INVOKED!");
    }

    /// Crash handler for windows
    ///
    /// # Safety
    /// Well, exception handling is not safe
    #[allow(clippy::too_many_lines)]
    pub unsafe fn inproc_crash_handler<E, EM, OF, Z>(
        exception_pointers: *mut EXCEPTION_POINTERS,
        data: &mut InProcessExecutorHandlerData,
    ) where
        E: Executor<EM, Z> + HasObservers,
        EM: EventFirer<State = E::State> + EventRestarter<State = E::State>,
        OF: Feedback<E::State>,
        E::State: HasExecutions + HasSolutions + HasCorpus,
        Z: HasObjective<Objective = OF, State = E::State>,
    {
        // Have we set a timer_before?
        if data.ptp_timer.is_some() {
            /*
                We want to prevent the timeout handler being run while the main thread is executing the crash handler
                Timeout handler runs if it has access to the critical section or data.in_target == 0
                Writing 0 to the data.in_target makes the timeout handler makes the timeout handler invalid.
            */
            compiler_fence(Ordering::SeqCst);
            EnterCriticalSection(data.critical as *mut CRITICAL_SECTION);
            compiler_fence(Ordering::SeqCst);
            data.in_target = 0;
            compiler_fence(Ordering::SeqCst);
            LeaveCriticalSection(data.critical as *mut CRITICAL_SECTION);
            compiler_fence(Ordering::SeqCst);
        }

        // Is this really crash?
        let mut is_crash = true;
        #[cfg(feature = "std")]
        if let Some(exception_pointers) = exception_pointers.as_mut() {
            let code = ExceptionCode::try_from(
                exception_pointers
                    .ExceptionRecord
                    .as_mut()
                    .unwrap()
                    .ExceptionCode
                    .0,
            )
            .unwrap();

            let exception_list = data.exceptions();
            if exception_list.contains(&code) {
                log::error!("Crashed with {code}");
            } else {
                // log::trace!("Exception code received, but {code} is not in CRASH_EXCEPTIONS");
                is_crash = false;
            }
        } else {
            log::error!("Crashed without exception (probably due to SIGABRT)");
        };

        if data.current_input_ptr.is_null() {
            {
                log::error!("Double crash\n");
                let crash_addr = exception_pointers
                    .as_mut()
                    .unwrap()
                    .ExceptionRecord
                    .as_mut()
                    .unwrap()
                    .ExceptionAddress as usize;

                log::error!(
                "We crashed at addr 0x{crash_addr:x}, but are not in the target... Bug in the fuzzer? Exiting."
                );
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
        } else {
            let executor = data.executor_mut::<E>();
            // reset timer
            if data.ptp_timer.is_some() {
                executor.post_run_reset();
                data.ptp_timer = None;
            }

            let state = data.state_mut::<E::State>();
            let fuzzer = data.fuzzer_mut::<Z>();
            let event_mgr = data.event_mgr_mut::<EM>();

            if is_crash {
                log::error!("Child crashed!");
            } else {
                // log::info!("Exception received!");
            }

            // Make sure we don't crash in the crash handler forever.
            if is_crash {
                let input = data.take_current_input::<<E::State as UsesInput>::Input>();

                run_observers_and_save_state::<E, EM, OF, Z>(
                    executor,
                    state,
                    input,
                    fuzzer,
                    event_mgr,
                    ExitKind::Crash,
                );
            } else {
                // This is not worth saving
            }
        }

        if is_crash {
            log::info!("Exiting!");
            ExitProcess(1);
        }
        // log::info!("Not Exiting!");
    }
}
