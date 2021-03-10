//! The InProcess Executor is a libfuzzer-like executor, that will simply call a function.
//! It should usually be paired with extra error-handling, such as a restarting event manager, to be effective.

use core::{
    ffi::c_void,
    marker::PhantomData,
    ptr::{self, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
};

#[cfg(unix)]
use crate::bolts::os::unix_signals::setup_signal_handler;
#[cfg(windows)]
use crate::bolts::os::windows_exceptions::setup_exception_handler;

use crate::{
    bolts::tuples::Named,
    corpus::Corpus,
    events::EventManager,
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::FeedbacksTuple,
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    state::{HasObjectives, HasSolutions},
    Error,
};

/// The inmem executor simply calls a target function, then returns afterwards.
pub struct InProcessExecutor<'a, H, I, OT>
where
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// The name of this executor instance, to address it from other components
    name: &'static str,
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: &'a mut H,
    /// The observers, observing each run
    observers: OT,
    phantom: PhantomData<I>,
}

impl<'a, H, I, OT> Executor<I> for InProcessExecutor<'a, H, I, OT>
where
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    #[inline]
    fn pre_exec<EM, S>(
        &mut self,
        _state: &mut S,
        _event_mgr: &mut EM,
        _input: &I,
    ) -> Result<(), Error> {
        #[cfg(unix)]
        unsafe {
            let data = &mut unix_signal_handler::GLOBAL_STATE;
            write_volatile(
                &mut data.current_input_ptr,
                _input as *const _ as *const c_void,
            );
            write_volatile(
                &mut data.observers_ptr,
                &self.observers as *const _ as *const c_void,
            );
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(&mut data.state_ptr, _state as *mut _ as *mut c_void);
            write_volatile(&mut data.event_mgr_ptr, _event_mgr as *mut _ as *mut c_void);
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(windows)]
        unsafe {
            let data = &mut windows_exception_handler::GLOBAL_STATE;
            write_volatile(
                &mut data.current_input_ptr,
                _input as *const _ as *const c_void,
            );
            write_volatile(
                &mut data.observers_ptr,
                &self.observers as *const _ as *const c_void,
            );
            // Direct raw pointers access /aliasing is pretty undefined behavior.
            // Since the state and event may have moved in memory, refresh them right before the signal may happen
            write_volatile(&mut data.state_ptr, _state as *mut _ as *mut c_void);
            write_volatile(&mut data.event_mgr_ptr, _event_mgr as *mut _ as *mut c_void);
            compiler_fence(Ordering::SeqCst);
        }
        Ok(())
    }

    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        let bytes = input.target_bytes();

        let ret = (self.harness_fn)(bytes.as_slice());
        #[cfg(unix)]
        unsafe {
            write_volatile(
                &mut unix_signal_handler::GLOBAL_STATE.current_input_ptr,
                ptr::null(),
            );
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(windows)]
        unsafe {
            write_volatile(
                &mut windows_exception_handler::GLOBAL_STATE.current_input_ptr,
                ptr::null(),
            );
            compiler_fence(Ordering::SeqCst);
        }
        Ok(())
    }
}

impl<'a, H, I, OT> Named for InProcessExecutor<'a, H, I, OT>
where
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    fn name(&self) -> &str {
        self.name
    }
}

impl<'a, H, I, OT> HasObservers<OT> for InProcessExecutor<'a, H, I, OT>
where
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
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

impl<'a, H, I, OT> InProcessExecutor<'a, H, I, OT>
where
    H: FnMut(&[u8]) -> ExitKind,
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depending on different corpus or state.
    /// * `name` - the name of this executor (to address it along the way)
    /// * `harness_fn` - the harness, executiong the function
    /// * `observers` - the observers observing the target during execution
    /// This may return an error on unix, if signal handler setup fails
    pub fn new<EM, OC, OFT, S>(
        name: &'static str,
        harness_fn: &'a mut H,
        observers: OT,
        _state: &mut S,
        _event_mgr: &mut EM,
    ) -> Result<Self, Error>
    where
        EM: EventManager<I, S>,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>,
    {
        #[cfg(unix)]
        unsafe {
            let data = &mut unix_signal_handler::GLOBAL_STATE;
            write_volatile(
                &mut data.crash_handler,
                unix_signal_handler::inproc_crash_handler::<EM, I, OC, OFT, OT, S>,
            );
            write_volatile(
                &mut data.timeout_handler,
                unix_signal_handler::inproc_timeout_handler::<EM, I, OC, OFT, OT, S>,
            );

            setup_signal_handler(data)?;
            compiler_fence(Ordering::SeqCst);
        }
        #[cfg(windows)]
        unsafe {
            let data = &mut windows_exception_handler::GLOBAL_STATE;
            write_volatile(
                &mut data.crash_handler,
                windows_exception_handler::inproc_crash_handler::<EM, I, OC, OFT, OT, S>,
            );
            //write_volatile(
            //    &mut data.timeout_handler,
            //    windows_exception_handler::inproc_timeout_handler::<EM, I, OC, OFT, OT, S>,
            //);

            setup_exception_handler(data)?;
            compiler_fence(Ordering::SeqCst);
        }

        Ok(Self {
            harness_fn,
            observers,
            name,
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

#[cfg(unix)]
mod unix_signal_handler {
    use alloc::vec::Vec;
    use core::ptr;
    use libc::{c_void, siginfo_t};
    #[cfg(feature = "std")]
    use std::{
        fs,
        io::{stdout, Write},
    };

    use crate::{
        bolts::os::unix_signals::{Handler, Signal},
        corpus::{Corpus, Testcase},
        events::{Event, EventManager},
        executors::ExitKind,
        feedbacks::FeedbacksTuple,
        inputs::{HasTargetBytes, Input},
        observers::ObserversTuple,
        state::{HasObjectives, HasSolutions},
    };

    // TODO merge GLOBAL_STATE with the Windows one

    /// Signal handling on unix systems needs some nasty unsafe.
    pub static mut GLOBAL_STATE: InProcessExecutorHandlerData = InProcessExecutorHandlerData {
        /// The state ptr for signal handling
        state_ptr: ptr::null_mut(),
        /// The event manager ptr for signal handling
        event_mgr_ptr: ptr::null_mut(),
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
        pub observers_ptr: *const c_void,
        pub current_input_ptr: *const c_void,
        pub crash_handler: unsafe fn(Signal, siginfo_t, c_void, data: &mut Self),
        pub timeout_handler: unsafe fn(Signal, siginfo_t, c_void, data: &mut Self),
    }

    unsafe impl Send for InProcessExecutorHandlerData {}
    unsafe impl Sync for InProcessExecutorHandlerData {}

    unsafe fn nop_handler(
        _signal: Signal,
        _info: siginfo_t,
        _void: c_void,
        _data: &mut InProcessExecutorHandlerData,
    ) {
    }

    #[cfg(unix)]
    impl Handler for InProcessExecutorHandlerData {
        fn handle(&mut self, signal: Signal, info: siginfo_t, void: c_void) {
            unsafe {
                let data = &mut GLOBAL_STATE;
                match signal {
                    Signal::SigUser2 | Signal::SigAlarm => {
                        (data.timeout_handler)(signal, info, void, data)
                    }
                    _ => (data.crash_handler)(signal, info, void, data),
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
            ]
        }
    }

    #[cfg(unix)]
    pub unsafe fn inproc_timeout_handler<EM, I, OC, OFT, OT, S>(
        _signal: Signal,
        _info: siginfo_t,
        _void: c_void,
        data: &mut InProcessExecutorHandlerData,
    ) where
        EM: EventManager<I, S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>,
        I: Input + HasTargetBytes,
    {
        let state = (data.state_ptr as *mut S).as_mut().unwrap();
        let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
        let observers = (data.observers_ptr as *const OT).as_ref().unwrap();

        if data.current_input_ptr.is_null() {
            #[cfg(feature = "std")]
            dbg!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing. Exiting");
        } else {
            #[cfg(feature = "std")]
            println!("Timeout in fuzz run.");
            #[cfg(feature = "std")]
            let _ = stdout().flush();

            let input = (data.current_input_ptr as *const I).as_ref().unwrap();
            data.current_input_ptr = ptr::null();

            let obj_fitness = state
                .objectives_mut()
                .is_interesting_all(&input, observers, ExitKind::Timeout)
                .expect("In timeout handler objectives failure.");
            if obj_fitness > 0 {
                state
                    .solutions_mut()
                    .add(Testcase::new(input.clone()))
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

    pub unsafe fn inproc_crash_handler<EM, I, OC, OFT, OT, S>(
        _signal: Signal,
        _info: siginfo_t,
        _void: c_void,
        data: &mut InProcessExecutorHandlerData,
    ) where
        EM: EventManager<I, S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>,
        I: Input + HasTargetBytes,
    {
        #[cfg(feature = "std")]
        println!("Crashed with {}", _signal);
        if !data.current_input_ptr.is_null() {
            let state = (data.state_ptr as *mut S).as_mut().unwrap();
            let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
            let observers = (data.observers_ptr as *const OT).as_ref().unwrap();

            #[cfg(feature = "std")]
            println!("Child crashed!");
            #[cfg(feature = "std")]
            let _ = stdout().flush();

            let input = (data.current_input_ptr as *const I).as_ref().unwrap();
            // Make sure we don't crash in the crash handler forever.
            data.current_input_ptr = ptr::null();

            let obj_fitness = state
                .objectives_mut()
                .is_interesting_all(&input, observers, ExitKind::Crash)
                .expect("In crash handler objectives failure.");
            if obj_fitness > 0 {
                let new_input = input.clone();
                state
                    .solutions_mut()
                    .add(Testcase::new(new_input))
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
        } else {
            #[cfg(feature = "std")]
            {
                println!("Double crash\n");
                #[cfg(target_os = "android")]
                let si_addr =
                    { ((_info._pad[0] as usize) | ((_info._pad[1] as usize) << 32)) as usize };
                #[cfg(not(target_os = "android"))]
                let si_addr = { _info.si_addr() as usize };

                println!(
                "We crashed at addr 0x{:x}, but are not in the target... Bug in the fuzzer? Exiting.",
                si_addr
                );
            }
            // let's yolo-cat the maps for debugging, if possible.
            #[cfg(all(target_os = "linux", feature = "std"))]
            match fs::read_to_string("/proc/self/maps") {
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
        }
    }
}

#[cfg(windows)]
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
        events::{Event, EventManager},
        executors::ExitKind,
        feedbacks::FeedbacksTuple,
        inputs::{HasTargetBytes, Input},
        observers::ObserversTuple,
        state::{HasObjectives, HasSolutions},
    };

    /// Signal handling on unix systems needs some nasty unsafe.
    pub static mut GLOBAL_STATE: InProcessExecutorHandlerData = InProcessExecutorHandlerData {
        /// The state ptr for signal handling
        state_ptr: ptr::null_mut(),
        /// The event manager ptr for signal handling
        event_mgr_ptr: ptr::null_mut(),
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

    pub unsafe fn inproc_crash_handler<EM, I, OC, OFT, OT, S>(
        code: ExceptionCode,
        exception_pointers: *mut EXCEPTION_POINTERS,
        data: &mut InProcessExecutorHandlerData,
    ) where
        EM: EventManager<I, S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>,
        I: Input + HasTargetBytes,
    {
        #[cfg(feature = "std")]
        println!("Crashed with {}", code);
        if !data.current_input_ptr.is_null() {
            let state = (data.state_ptr as *mut S).as_mut().unwrap();
            let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
            let observers = (data.observers_ptr as *const OT).as_ref().unwrap();

            #[cfg(feature = "std")]
            println!("Child crashed!");
            #[cfg(feature = "std")]
            let _ = stdout().flush();

            let input = (data.current_input_ptr as *const I).as_ref().unwrap();
            // Make sure we don't crash in the crash handler forever.
            data.current_input_ptr = ptr::null();

            let obj_fitness = state
                .objectives_mut()
                .is_interesting_all(&input, observers, ExitKind::Crash)
                .expect("In crash handler objectives failure.");
            if obj_fitness > 0 {
                let new_input = input.clone();
                state
                    .solutions_mut()
                    .add(Testcase::new(new_input))
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
        inputs::Input,
    };

    fn test_harness_fn_nop<E: Executor<I>, I: Input>(_executor: &E, _buf: &[u8]) -> ExitKind {
        ExitKind::Ok
    }

    #[test]
    fn test_inmem_exec() {
        use crate::inputs::NopInput;

        let mut in_process_executor = InProcessExecutor::<NopInput, ()> {
            harness_fn: test_harness_fn_nop,
            observers: tuple_list!(),
            name: "main",
            phantom: PhantomData,
        };
        let mut input = NopInput {};
        assert!(in_process_executor.run_target(&mut input).is_ok());
    }
}

