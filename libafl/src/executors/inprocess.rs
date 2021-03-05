//! The InProcess Executor is a libfuzzer-like executor, that will simply call a function.
//! It should usually be paired with extra error-handling, such as a restarting event manager, to be effective.

use core::marker::PhantomData;
#[cfg(unix)]
use core::ptr;

#[cfg(unix)]
use crate::bolts::os::unix_signals::{c_void, setup_signal_handler};
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

/// The inmem executor harness
type HarnessFunction<E> = fn(&E, &[u8]) -> ExitKind;

/// The inmem executor simply calls a target function, then returns afterwards.
pub struct InProcessExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// The name of this executor instance, to address it from other components
    name: &'static str,
    /// The harness function, being executed for each fuzzing loop execution
    harness_fn: HarnessFunction<Self>,
    /// The observers, observing each run
    observers: OT,
    phantom: PhantomData<I>,
}

impl<I, OT> Executor<I> for InProcessExecutor<I, OT>
where
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
            unix_signal_handler::GLOBAL_STATE.current_input_ptr =
                _input as *const _ as *const c_void;
        }
        Ok(())
    }

    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        let bytes = input.target_bytes();
        let ret = (self.harness_fn)(self, bytes.as_slice());
        #[cfg(unix)]
        unsafe {
            unix_signal_handler::GLOBAL_STATE.current_input_ptr = ptr::null();
        }
        Ok(ret)
    }
}

impl<I, OT> Named for InProcessExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    fn name(&self) -> &str {
        self.name
    }
}

impl<I, OT> HasObservers<OT> for InProcessExecutor<I, OT>
where
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

impl<I, OT> InProcessExecutor<I, OT>
where
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
        harness_fn: HarnessFunction<Self>,
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
            let mut data = &mut unix_signal_handler::GLOBAL_STATE;
            data.state_ptr = _state as *mut _ as *mut c_void;
            data.event_mgr_ptr = _event_mgr as *mut _ as *mut c_void;
            data.observers_ptr = &observers as *const _ as *const c_void;
            data.crash_handler = unix_signal_handler::inproc_crash_handler::<EM, I, OC, OFT, OT, S>;
            data.timeout_handler =
                unix_signal_handler::inproc_timeout_handler::<EM, I, OC, OFT, OT, S>;

            setup_signal_handler(data)?;
        }

        Ok(Self {
            harness_fn,
            observers,
            name,
            phantom: PhantomData,
        })
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
                    Signal::SigUser2 => (data.timeout_handler)(signal, info, void, data),
                    _ => (data.crash_handler)(signal, info, void, data),
                }
            }
        }

        fn signals(&self) -> Vec<Signal> {
            vec![
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
                .is_interesting_all(&input, observers, ExitKind::Crash)
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
            // TODO: on_crash_fn: Box::new(|_, _, _, _, _| ()),
            observers: tuple_list!(),
            name: "main",
            phantom: PhantomData,
        };
        let mut input = NopInput {};
        assert!(in_process_executor.run_target(&mut input).is_ok());
    }
}
