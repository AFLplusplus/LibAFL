//! The [`InProcessExecutor`] is a libfuzzer-like executor, that will simply call a function.
//! It should usually be paired with extra error-handling, such as a restarting event manager, to be effective.

use core::marker::PhantomData;

#[cfg(any(unix, all(windows, feature = "std")))]
use core::{
    ffi::c_void,
    ptr::{self, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
};

#[cfg(unix)]
use crate::bolts::os::unix_signals::setup_signal_handler;
#[cfg(all(windows, feature = "std"))]
use crate::bolts::os::windows_exceptions::setup_exception_handler;

use crate::{
    corpus::Corpus,
    events::{EventFirer, EventRestarter},
    executors::{Executor, ExitKind, HasExecHooksTuple, HasObservers, HasObserversHooks},
    feedbacks::Feedback,
    fuzzer::HasObjective,
    inputs::Input,
    observers::ObserversTuple,
    state::HasSolutions,
    Error,
};

/// The inmem executor simply calls a target function, then returns afterwards.
pub struct InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple,
{
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: &'a mut H,
    /// The observers, observing each run
    observers: OT,
    phantom: PhantomData<(I, S)>,
}

impl<'a, EM, H, I, OT, S, Z> Executor<EM, I, S, Z> for InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple,
{
    #[inline]
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        #[cfg(unix)]
        unsafe {
            let data = &mut unix_signal_handler::GLOBAL_STATE;
            write_volatile(
                &mut data.current_input_ptr,
                input as *const _ as *const c_void,
            );
            write_volatile(
                &mut data.observers_ptr,
                &self.observers as *const _ as *const c_void,
            );
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(&mut data.state_ptr, state as *mut _ as *mut c_void);
            write_volatile(&mut data.event_mgr_ptr, mgr as *mut _ as *mut c_void);
            write_volatile(&mut data.fuzzer_ptr, fuzzer as *mut _ as *mut c_void);
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(all(windows, feature = "std"))]
        unsafe {
            let data = &mut windows_exception_handler::GLOBAL_STATE;
            write_volatile(
                &mut data.current_input_ptr,
                input as *const _ as *const c_void,
            );
            write_volatile(
                &mut data.observers_ptr,
                &self.observers as *const _ as *const c_void,
            );
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(&mut data.state_ptr, state as *mut _ as *mut c_void);
            write_volatile(&mut data.event_mgr_ptr, mgr as *mut _ as *mut c_void);
            write_volatile(&mut data.fuzzer_ptr, fuzzer as *mut _ as *mut c_void);
            compiler_fence(Ordering::SeqCst);
        }

        let ret = (self.harness_fn)(input);

        #[cfg(unix)]
        unsafe {
            write_volatile(
                &mut unix_signal_handler::GLOBAL_STATE.current_input_ptr,
                ptr::null(),
            );
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(all(windows, feature = "std"))]
        unsafe {
            write_volatile(
                &mut windows_exception_handler::GLOBAL_STATE.current_input_ptr,
                ptr::null(),
            );
            compiler_fence(Ordering::SeqCst);
        }

        Ok(ret)
    }
}

impl<'a, H, I, OT, S> HasObservers<OT> for InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple,
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

impl<'a, EM, H, I, OT, S, Z> HasObserversHooks<EM, I, OT, S, Z>
    for InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple + HasExecHooksTuple<EM, I, S, Z>,
{
}

impl<'a, H, I, OT, S> InProcessExecutor<'a, H, I, OT, S>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple,
{
    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `harness_fn` - the harness, executiong the function
    /// * `observers` - the observers observing the target during execution
    /// This may return an error on unix, if signal handler setup fails
    pub fn new<EM, OC, OF, Z>(
        harness_fn: &'a mut H,
        observers: OT,
        _fuzzer: &mut Z,
        _state: &mut S,
        _event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventFirer<I, S> + EventRestarter<S>,
        OC: Corpus<I>,
        OF: Feedback<I, S>,
        S: HasSolutions<OC, I>,
        Z: HasObjective<I, OF, S>,
    {
        #[cfg(unix)]
        unsafe {
            let data = &mut unix_signal_handler::GLOBAL_STATE;
            write_volatile(
                &mut data.crash_handler,
                unix_signal_handler::inproc_crash_handler::<EM, I, OC, OF, OT, S, Z>,
            );
            write_volatile(
                &mut data.timeout_handler,
                unix_signal_handler::inproc_timeout_handler::<EM, I, OC, OF, OT, S, Z>,
            );

            setup_signal_handler(data)?;
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(all(windows, feature = "std"))]
        unsafe {
            let data = &mut windows_exception_handler::GLOBAL_STATE;
            write_volatile(
                &mut data.crash_handler,
                windows_exception_handler::inproc_crash_handler::<EM, I, OC, OF, OT, S, Z>,
            );
            //write_volatile(
            //    &mut data.timeout_handler,
            //    windows_exception_handler::inproc_timeout_handler::<EM, I, OC, OF, OT, S, Z>,
            //);

            setup_exception_handler(data)?;
            compiler_fence(Ordering::SeqCst);
        }

        Ok(Self {
            harness_fn,
            observers,
            phantom: PhantomData,
        })
    }

    /// Retrieve the harness function.
    #[inline]
    pub fn harness(&self) -> &H {
        &self.harness_fn
    }

    /// Retrieve the harness function for a mutable reference.
    #[inline]
    pub fn harness_mut(&mut self) -> &mut H {
        self.harness_fn
    }
}

#[cfg(unix)]
mod unix_signal_handler {
    use alloc::vec::Vec;
    use core::ptr;
    use libc::{c_void, siginfo_t, ucontext_t};
    #[cfg(feature = "std")]
    use std::io::{stdout, Write};

    use crate::{
        bolts::os::unix_signals::{Handler, Signal},
        corpus::{Corpus, Testcase},
        events::{Event, EventFirer, EventRestarter},
        executors::ExitKind,
        feedbacks::Feedback,
        fuzzer::HasObjective,
        inputs::Input,
        observers::ObserversTuple,
        state::HasSolutions,
    };

    // TODO merge GLOBAL_STATE with the Windows one

    /// Signal handling on unix systems needs some nasty unsafe.
    pub static mut GLOBAL_STATE: InProcessExecutorHandlerData = InProcessExecutorHandlerData {
        /// The state ptr for signal handling
        state_ptr: ptr::null_mut(),
        /// The event manager ptr for signal handling
        event_mgr_ptr: ptr::null_mut(),
        /// The fuzzer ptr for signal handling
        fuzzer_ptr: ptr::null_mut(),
        /// The observers ptr for signal handling
        observers_ptr: ptr::null(),
        /// The current input for signal handling
        current_input_ptr: ptr::null(),
        /// The crash handler fn
        crash_handler: nop_handler,
        /// The timeout handler fn
        timeout_handler: nop_handler,
    };

    pub struct InProcessExecutorHandlerData {
        pub state_ptr: *mut c_void,
        pub event_mgr_ptr: *mut c_void,
        pub fuzzer_ptr: *mut c_void,
        pub observers_ptr: *const c_void,
        pub current_input_ptr: *const c_void,
        pub crash_handler: unsafe fn(Signal, siginfo_t, &mut ucontext_t, data: &mut Self),
        pub timeout_handler: unsafe fn(Signal, siginfo_t, &mut ucontext_t, data: &mut Self),
    }

    unsafe impl Send for InProcessExecutorHandlerData {}
    unsafe impl Sync for InProcessExecutorHandlerData {}

    unsafe fn nop_handler(
        _signal: Signal,
        _info: siginfo_t,
        _context: &mut ucontext_t,
        _data: &mut InProcessExecutorHandlerData,
    ) {
    }

    #[cfg(unix)]
    impl Handler for InProcessExecutorHandlerData {
        fn handle(&mut self, signal: Signal, info: siginfo_t, context: &mut ucontext_t) {
            unsafe {
                let data = &mut GLOBAL_STATE;
                match signal {
                    Signal::SigUser2 | Signal::SigAlarm => {
                        (data.timeout_handler)(signal, info, context, data)
                    }
                    _ => (data.crash_handler)(signal, info, context, data),
                }
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

    #[cfg(unix)]
    pub unsafe fn inproc_timeout_handler<EM, I, OC, OF, OT, S, Z>(
        _signal: Signal,
        _info: siginfo_t,
        _context: &mut ucontext_t,
        data: &mut InProcessExecutorHandlerData,
    ) where
        EM: EventFirer<I, S> + EventRestarter<S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OF: Feedback<I, S>,
        S: HasSolutions<OC, I>,
        I: Input,
        Z: HasObjective<I, OF, S>,
    {
        let state = (data.state_ptr as *mut S).as_mut().unwrap();
        let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
        let fuzzer = (data.fuzzer_ptr as *mut Z).as_mut().unwrap();
        let observers = (data.observers_ptr as *const OT).as_ref().unwrap();

        if data.current_input_ptr.is_null() {
            #[cfg(feature = "std")]
            dbg!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing. Exiting");
        } else {
            #[cfg(feature = "std")]
            println!("Timeout in fuzz run.");
            #[cfg(feature = "std")]
            let _res = stdout().flush();

            let input = (data.current_input_ptr as *const I).as_ref().unwrap();
            data.current_input_ptr = ptr::null();

            let interesting = fuzzer
                .objective_mut()
                .is_interesting(state, event_mgr, &input, observers, &ExitKind::Timeout)
                .expect("In timeout handler objective failure.");

            if interesting {
                let mut new_testcase = Testcase::new(input.clone());
                fuzzer
                    .objective_mut()
                    .append_metadata(state, &mut new_testcase)
                    .expect("Failed adding metadata");
                state
                    .solutions_mut()
                    .add(new_testcase)
                    .expect("In timeout handler solutions failure.");
                event_mgr
                    .fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                        },
                    )
                    .expect("Could not send timeouting input");
            }

            event_mgr.on_restart(state).unwrap();

            #[cfg(feature = "std")]
            println!("Waiting for broker...");
            event_mgr.await_restart_safe();
            #[cfg(feature = "std")]
            println!("Bye!");

            event_mgr.await_restart_safe();

            libc::_exit(1);
        }
    }

    /// Crash-Handler for in-process fuzzing.
    /// Will be used for signal handling.
    /// It will store the current State to shmem, then exit.
    #[allow(clippy::too_many_lines)]
    pub unsafe fn inproc_crash_handler<EM, I, OC, OF, OT, S, Z>(
        _signal: Signal,
        _info: siginfo_t,
        _context: &mut ucontext_t,
        data: &mut InProcessExecutorHandlerData,
    ) where
        EM: EventFirer<I, S> + EventRestarter<S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OF: Feedback<I, S>,
        S: HasSolutions<OC, I>,
        I: Input,
        Z: HasObjective<I, OF, S>,
    {
        #[cfg(all(target_os = "android", target_arch = "aarch64"))]
        let _context = *(((_context as *mut _ as *mut c_void as usize) + 128) as *mut c_void
            as *mut ucontext_t);

        #[cfg(feature = "std")]
        println!("Crashed with {}", _signal);
        if data.current_input_ptr.is_null() {
            #[cfg(feature = "std")]
            {
                println!("Double crash\n");
                #[cfg(target_os = "android")]
                let si_addr = (_info._pad[0] as i64) | ((_info._pad[1] as i64) << 32);
                #[cfg(not(target_os = "android"))]
                let si_addr = { _info.si_addr() as usize };

                println!(
                "We crashed at addr 0x{:x}, but are not in the target... Bug in the fuzzer? Exiting.",
                si_addr
                );
            }
            // let's yolo-cat the maps for debugging, if possible.
            #[cfg(all(target_os = "linux", feature = "std"))]
            match std::fs::read_to_string("/proc/self/maps") {
                Ok(maps) => println!("maps:\n{}", maps),
                Err(e) => println!("Couldn't load mappings: {:?}", e),
            };
            #[cfg(feature = "std")]
            {
                println!("Type QUIT to restart the child");
                let mut line = String::new();
                while line.trim() != "QUIT" {
                    std::io::stdin().read_line(&mut line).unwrap();
                }
            }

            // TODO tell the parent to not restart
            libc::_exit(1);
        } else {
            let state = (data.state_ptr as *mut S).as_mut().unwrap();
            let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
            let fuzzer = (data.fuzzer_ptr as *mut Z).as_mut().unwrap();
            let observers = (data.observers_ptr as *const OT).as_ref().unwrap();

            #[cfg(feature = "std")]
            println!("Child crashed!");

            #[allow(clippy::non_ascii_literal)]
            #[cfg(all(
                feature = "std",
                any(target_os = "linux", target_os = "android"),
                target_arch = "aarch64"
            ))]
            {
                use crate::bolts::os::find_mapping_for_address;
                println!("{:━^100}", " CRASH ");
                println!(
                    "Received signal {} at 0x{:016x}, fault address: 0x{:016x}",
                    _signal, _context.uc_mcontext.pc, _context.uc_mcontext.fault_address
                );
                if let Ok((start, _, _, path)) =
                    find_mapping_for_address(_context.uc_mcontext.pc as usize)
                {
                    println!(
                        "pc is at offset 0x{:08x} in  {}",
                        _context.uc_mcontext.pc as usize - start,
                        path
                    );
                }

                println!("{:━^100}", " REGISTERS ");
                for reg in 0..31 {
                    print!(
                        "x{:02}: 0x{:016x} ",
                        reg, _context.uc_mcontext.regs[reg as usize]
                    );
                    if reg % 4 == 3 {
                        println!();
                    }
                }
                println!("pc : 0x{:016x} ", _context.uc_mcontext.pc);

                //println!("{:━^100}", " BACKTRACE ");
                //println!("{:?}", backtrace::Backtrace::new())
            }

            #[cfg(feature = "std")]
            let _res = stdout().flush();

            let input = (data.current_input_ptr as *const I).as_ref().unwrap();
            // Make sure we don't crash in the crash handler forever.
            data.current_input_ptr = ptr::null();

            let interesting = fuzzer
                .objective_mut()
                .is_interesting(state, event_mgr, &input, observers, &ExitKind::Crash)
                .expect("In crash handler objective failure.");

            if interesting {
                let new_input = input.clone();
                let mut new_testcase = Testcase::new(new_input);
                fuzzer
                    .objective_mut()
                    .append_metadata(state, &mut new_testcase)
                    .expect("Failed adding metadata");
                state
                    .solutions_mut()
                    .add(new_testcase)
                    .expect("In crash handler solutions failure.");
                event_mgr
                    .fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                        },
                    )
                    .expect("Could not send crashing input");
            }

            event_mgr.on_restart(state).unwrap();

            #[cfg(feature = "std")]
            println!("Waiting for broker...");
            event_mgr.await_restart_safe();
            #[cfg(feature = "std")]
            println!("Bye!");

            libc::_exit(1);
        }
    }
}

#[cfg(all(windows, feature = "std"))]
mod windows_exception_handler {
    use alloc::vec::Vec;
    use core::{ffi::c_void, ptr};
    #[cfg(feature = "std")]
    use std::io::{stdout, Write};

    use crate::{
        bolts::{
            bindings::windows::win32::system_services::ExitProcess,
            os::windows_exceptions::{
                ExceptionCode, Handler, CRASH_EXCEPTIONS, EXCEPTION_POINTERS,
            },
        },
        corpus::{Corpus, Testcase},
        events::{Event, EventFirer, EventRestarter},
        executors::ExitKind,
        feedbacks::Feedback,
        fuzzer::HasObjective,
        inputs::Input,
        observers::ObserversTuple,
        state::HasSolutions,
    };

    /// Signal handling on unix systems needs some nasty unsafe.
    pub static mut GLOBAL_STATE: InProcessExecutorHandlerData = InProcessExecutorHandlerData {
        /// The state ptr for signal handling
        state_ptr: ptr::null_mut(),
        /// The event manager ptr for signal handling
        event_mgr_ptr: ptr::null_mut(),
        /// The fuzzer ptr for signal handling
        fuzzer_ptr: ptr::null_mut(),
        /// The observers ptr for signal handling
        observers_ptr: ptr::null(),
        /// The current input for signal handling
        current_input_ptr: ptr::null(),
        /// The crash handler fn
        crash_handler: nop_handler,
        // The timeout handler fn
        //timeout_handler: nop_handler,
    };

    pub struct InProcessExecutorHandlerData {
        pub state_ptr: *mut c_void,
        pub event_mgr_ptr: *mut c_void,
        pub fuzzer_ptr: *mut c_void,
        pub observers_ptr: *const c_void,
        pub current_input_ptr: *const c_void,
        pub crash_handler: unsafe fn(ExceptionCode, *mut EXCEPTION_POINTERS, &mut Self),
        //pub timeout_handler: unsafe fn(ExceptionCode, *mut EXCEPTION_POINTERS, &mut Self),
    }

    unsafe impl Send for InProcessExecutorHandlerData {}
    unsafe impl Sync for InProcessExecutorHandlerData {}

    unsafe fn nop_handler(
        _code: ExceptionCode,
        _exception_pointers: *mut EXCEPTION_POINTERS,
        _data: &mut InProcessExecutorHandlerData,
    ) {
    }

    impl Handler for InProcessExecutorHandlerData {
        fn handle(&mut self, code: ExceptionCode, exception_pointers: *mut EXCEPTION_POINTERS) {
            unsafe {
                let data = &mut GLOBAL_STATE;
                (data.crash_handler)(code, exception_pointers, data)
            }
        }

        fn exceptions(&self) -> Vec<ExceptionCode> {
            CRASH_EXCEPTIONS.to_vec()
        }
    }

    pub unsafe fn inproc_crash_handler<EM, I, OC, OF, OT, S, Z>(
        code: ExceptionCode,
        exception_pointers: *mut EXCEPTION_POINTERS,
        data: &mut InProcessExecutorHandlerData,
    ) where
        EM: EventFirer<I, S> + EventRestarter<S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OF: Feedback<I, S>,
        S: HasSolutions<OC, I>,
        I: Input,
        Z: HasObjective<I, OF, S>,
    {
        #[cfg(feature = "std")]
        println!("Crashed with {}", code);
        if !data.current_input_ptr.is_null() {
            let state = (data.state_ptr as *mut S).as_mut().unwrap();
            let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
            let fuzzer = (data.fuzzer_ptr as *mut Z).as_mut().unwrap();
            let observers = (data.observers_ptr as *const OT).as_ref().unwrap();

            #[cfg(feature = "std")]
            println!("Child crashed!");
            #[cfg(feature = "std")]
            let _ = stdout().flush();

            let input = (data.current_input_ptr as *const I).as_ref().unwrap();
            // Make sure we don't crash in the crash handler forever.
            data.current_input_ptr = ptr::null();

            let interesting = fuzzer
                .objective_mut()
                .is_interesting(state, event_mgr, &input, observers, &ExitKind::Crash)
                .expect("In crash handler objective failure.");

            if interesting {
                let new_input = input.clone();
                let mut new_testcase = Testcase::new(new_input);
                fuzzer
                    .objective_mut()
                    .append_metadata(state, &mut new_testcase)
                    .expect("Failed adding metadata");
                state
                    .solutions_mut()
                    .add(new_testcase)
                    .expect("In crash handler solutions failure.");
                event_mgr
                    .fire(
                        state,
                        Event::Objective {
                            objective_size: state.solutions().count(),
                        },
                    )
                    .expect("Could not send crashing input");
            }

            event_mgr.on_restart(state).unwrap();

            #[cfg(feature = "std")]
            println!("Waiting for broker...");
            event_mgr.await_restart_safe();
            #[cfg(feature = "std")]
            println!("Bye!");

            ExitProcess(1);
        } else {
            #[cfg(feature = "std")]
            {
                println!("Double crash\n");
                let crash_addr = exception_pointers
                    .as_mut()
                    .unwrap()
                    .exception_record
                    .as_mut()
                    .unwrap()
                    .exception_address as usize;

                println!(
                "We crashed at addr 0x{:x}, but are not in the target... Bug in the fuzzer? Exiting.",
                    crash_addr
                );
            }
            #[cfg(feature = "std")]
            {
                println!("Type QUIT to restart the child");
                let mut line = String::new();
                while line.trim() != "QUIT" {
                    std::io::stdin().read_line(&mut line).unwrap();
                }
            }

            // TODO tell the parent to not restart
            ExitProcess(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use crate::{
        bolts::tuples::tuple_list,
        executors::{Executor, ExitKind, InProcessExecutor},
        inputs::NopInput,
    };

    #[test]
    fn test_inmem_exec() {
        let mut harness = |_buf: &NopInput| ExitKind::Ok;

        let mut in_process_executor = InProcessExecutor::<_, NopInput, (), ()> {
            harness_fn: &mut harness,
            observers: tuple_list!(),
            phantom: PhantomData,
        };
        let input = NopInput {};
        assert!(in_process_executor
            .run_target(&mut (), &mut (), &mut (), &input)
            .is_ok());
    }
}
