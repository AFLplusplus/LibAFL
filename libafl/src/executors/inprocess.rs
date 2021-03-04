//! The InProcess Executor is a libfuzzer-like executor, that will simply call a function.
//! It should usually be paired with extra error-handling, such as a restarting event manager, to be effective.

use core::{
    cell::UnsafeCell,
    marker::PhantomData,
};

use crate::{
    bolts::tuples::Named,
    corpus::{Corpus, Testcase},
    events::{Event, EventManager},
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::FeedbacksTuple,
    inputs::{HasTargetBytes, Input},
    observers::ObserversTuple,
    state::{HasObjectives, HasSolutions},
    Error,
};
#[cfg(all(feature = "std", unix))]
use crate::bolts::os::unix_signals::{
    setup_signal_handler, Handler, siginfo_t, Signal, c_void
};
#[cfg(all(feature = "std", unix))]
use std::{
    fs,
    io::{stdout, Write},
    ptr,
    sync::Mutex,
};

use lazy_static::lazy_static;

struct InProcessExecutorHandlerData {
    state_ptr: *mut c_void,
    event_mgr_ptr: *mut c_void,
    observers_ptr: *const c_void,
    current_input_ptr: *const c_void,
}

unsafe impl Send for InProcessExecutorHandlerData {}

impl InProcessExecutorHandlerData {
    fn new() -> Self {
        InProcessExecutorHandlerData {
            state_ptr: ptr::null_mut(),
            event_mgr_ptr: ptr::null_mut(),
            observers_ptr: ptr::null(),
            current_input_ptr: ptr::null(),
        }
    }
}


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
    current_input_ptr: *const c_void,
    crash_handler: unsafe fn (Signal, siginfo_t, c_void),
    timeout_handler: unsafe fn (Signal, siginfo_t, c_void),
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
        input: &I,
    ) -> Result<(), Error>
    {
        self.current_input_ptr = input as *const _ as *const c_void;
        Ok(())
    }

    #[inline]
    fn run_target(&mut self, input: &I) -> Result<ExitKind, Error> {
        let bytes = input.target_bytes();
        let ret = (self.harness_fn)(self, bytes.as_slice());
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

impl<I, OT> Handler for InProcessExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    fn handle(&mut self, signal: Signal, info: siginfo_t, void: c_void) {
        match signal {
            Signal::SigUser2 => (self.timeout_handler)(signal, info, void),
            _ => (self.crash_handler)(signal, info, void),
        }
    }

    fn signals(&self) -> Vec<Signal> {
        vec![
            Signal::SigUser2,

            Signal::SigAbort,
            Signal::SigBus,
            Signal::SigPipe,
            Signal::SigFloatingPointException,
            Signal::SigKill,
            Signal::SigIllegalInstruction,
            Signal::SigSegmentationFault,
        ]
    }
}

unsafe fn inproc_timeout_handler<EM, I, OC, OFT, OT, S>(_signal: Signal, _info: siginfo_t, _void: c_void)
where
        EM: EventManager<I, S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>,
        I: Input + HasTargetBytes,
{
    let data = GLOBAL_STATE.lock().unwrap();
    let state = (data.state_ptr as *mut S).as_mut().unwrap();
    let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
    let observers = (data.observers_ptr as *const OT).as_ref().unwrap();

    if data.current_input_ptr.is_null() {
            dbg!("TIMEOUT or SIGUSR2 happened, but currently not fuzzing. Exiting");
    } else {
        println!("Timeout in fuzz run.");
        let _ = stdout().flush();

        let input = (data.current_input_ptr as *const I).as_ref().unwrap();

        let obj_fitness = state
            .objectives_mut()
            .is_interesting_all(&input, observers, ExitKind::Crash)
            .expect("In timeout handler objectives failure.");
        if obj_fitness > 0 {
            state
                .solutions_mut()
                .add(Testcase::new(input.clone()))
                .expect("In timeout handler solutions failure.");
            event_mgr.fire(
                state,
                Event::Objective {
                    objective_size: state.solutions().count(),
                },
            )
            .expect("Could not send timeouting input");
        }

        event_mgr.on_restart(state).unwrap();

        println!("Waiting for broker...");
        event_mgr.await_restart_safe();
        println!("Bye!");

        event_mgr.await_restart_safe();

        std::process::exit(1);
    }

}

unsafe fn inproc_crash_handler<EM, I, OC, OFT, OT, S>(_signal: Signal, info: siginfo_t, _void: c_void)
where
        EM: EventManager<I, S>,
        OT: ObserversTuple,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>,
        I: Input + HasTargetBytes,
{
    let data = GLOBAL_STATE.lock().unwrap();
    let state = (data.state_ptr as *mut S).as_mut().unwrap();
    let event_mgr = (data.event_mgr_ptr as *mut EM).as_mut().unwrap();
    let observers = (data.observers_ptr as *const OT).as_ref().unwrap();

    if data.current_input_ptr == ptr::null() {
        #[cfg(target_os = "android")]
        let si_addr = { ((info._pad[0] as usize) | ((info._pad[1] as usize) << 32)) as usize };
        #[cfg(not(target_os = "android"))]
        let si_addr = { info.si_addr() as usize };

        println!(
            "We crashed at addr 0x{:x}, but are not in the target... Bug in the fuzzer? Exiting.",
            si_addr
        );
        // let's yolo-cat the maps for debugging, if possible.
        #[cfg(target_os = "linux")]
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
        std::process::exit(1);
    }

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
        .expect("In crash handler objectives failure.".into());
    if obj_fitness > 0 {
        state
            .solutions_mut()
            .add(Testcase::new(input.clone()))
            .expect("In crash handler solutions failure.".into());
        event_mgr.fire(
            state,
            Event::Objective {
                objective_size: state.solutions().count(),
            },
        )
        .expect("Could not send crashing input".into());
    }

    event_mgr.on_restart(state).unwrap();

    println!("Waiting for broker...");
    event_mgr.await_restart_safe();
    println!("Bye!");

    std::process::exit(1);
}

lazy_static!{
    static ref GLOBAL_STATE: Mutex<InProcessExecutorHandlerData> =
        Mutex::new(InProcessExecutorHandlerData::new());
}
impl<I, OT> InProcessExecutor<I, OT>
where
    I: Input + HasTargetBytes,
    OT: ObserversTuple,
{
    /// Create a new in mem executor.
    /// Caution: crash and restart in one of them will lead to odd behavior if multiple are used,
    /// depnding on different corpus or state.
    /// * `name` - the name of this executor (to address it along the way)
    /// * `harness_fn` - the harness, executiong the function
    /// * `observers` - the observers observing the target during execution
    pub fn new<EM, OC, OFT, S>(
        name: &'static str,
        harness_fn: HarnessFunction<Self>,
        observers: OT,
        state: &mut S,
        event_mgr: &mut EM,
    ) -> Self
    where
        EM: EventManager<I, S>,
        OC: Corpus<I>,
        OFT: FeedbacksTuple<I>,
        S: HasObjectives<OFT, I> + HasSolutions<OC, I>
    {

        let mut newobj = Self {
            harness_fn,
            observers,
            name,
            current_input_ptr: ptr::null(),
            crash_handler: inproc_crash_handler::<EM, I, OC, OFT, OT, S>,
            timeout_handler: inproc_timeout_handler::<EM, I, OC, OFT, OT, S>,
            phantom: PhantomData,
        };

        let data = GLOBAL_STATE.lock().unwrap();
        data.state_ptr = state as *mut _ as *mut c_void;
        data.event_mgr_ptr = state as *mut _ as *mut c_void;

        unsafe {
            setup_signal_handler(&mut newobj);
        }
        newobj
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
