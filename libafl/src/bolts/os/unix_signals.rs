extern crate libc;

use std::{
    cell::UnsafeCell,
    collections::HashMap,
    convert::TryFrom,
    fmt::{Display, Formatter},
    mem,
    ptr,
    sync::Mutex,
};

use libc::{
    c_int, malloc, sigaction, sigaltstack, stack_t, sigemptyset, SA_NODEFER, SA_ONSTACK,
    SA_SIGINFO, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGPIPE, SIGSEGV, SIGUSR2, SIGALRM, SIGHUP,
    SIGKILL, SIGQUIT,SIGTERM, SIGINT
};

use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::Error;

use lazy_static::lazy_static;

pub use libc::{c_void, siginfo_t};

#[derive(IntoPrimitive, TryFromPrimitive, Hash, Clone, Copy)]
#[repr(i32)]
pub enum Signal {
    SigAbort = SIGABRT,
    SigBus = SIGBUS,
    SigFloatingPointException = SIGFPE,
    SigIllegalInstruction = SIGILL,
    SigPipe = SIGPIPE,
    SigSegmentationFault = SIGSEGV,
    SigUser2 = SIGUSR2,
    SigAlarm = SIGALRM,
    SigHangUp = SIGHUP,
    SigKill = SIGKILL,
    SigQuit = SIGQUIT,
    SigTerm = SIGTERM,
    SigInterrupt = SIGINT,
}

pub static CrashSignals: &[Signal] = &[
    Signal::SigAbort,
    Signal::SigBus,
    Signal::SigFloatingPointException,
    Signal::SigIllegalInstruction,
    Signal::SigPipe,
    Signal::SigSegmentationFault,
];

impl PartialEq for Signal {
    fn eq(&self, other: &Self) -> bool {
        *self as i32 == *other as i32
    }
}

impl Eq for Signal {}

unsafe impl Sync for Signal {}

impl Display for Signal {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            Signal::SigAbort => write!(f, "SIGABRT"),
            Signal::SigBus => write!(f, "SIGBUS"),
            Signal::SigFloatingPointException => write!(f, "SIGFPE"),
            Signal::SigIllegalInstruction => write!(f, "SIGILL"),
            Signal::SigPipe => write!(f, "SIGPIPE"),
            Signal::SigSegmentationFault => write!(f, "SIGSEGV"),
            Signal::SigUser2 => write!(f, "SIGUSR2"),
            Signal::SigAlarm => write!(f, "SIGALRM"),
            Signal::SigHangUp => write!(f, "SIGHUP"),
            Signal::SigKill => write!(f, "SIGKILL"),
            Signal::SigQuit => write!(f, "SIGQUIT"),
            Signal::SigTerm => write!(f, "SIGTERM"),
            Signal::SigInterrupt => write!(f, "SIGINT"),
        };

        Ok(())
    }
}

pub trait Handler {
    /// Handle a signal
    fn handle(&mut self, signal: Signal, info: siginfo_t, _void: c_void);
    /// Return a list of signals to handle
    fn signals(&self) -> Vec<Signal>;
}

struct HandlerHolder {
    handler: UnsafeCell<*mut dyn Handler>,
}

unsafe impl Send for HandlerHolder {}


/// Let's get 8 mb for now.
const SIGNAL_STACK_SIZE: usize = 2 << 22;
/// To be able to handle SIGSEGV when the stack is exhausted, we need our own little stack space.
static mut SIGNAL_STACK_PTR: *mut c_void = ptr::null_mut();

lazy_static!{
    /// Keep track of which handler is registered for which signal
    static ref SIGNAL_HANDLERS: Mutex<HashMap<Signal, HandlerHolder>> = Mutex::new(HashMap::new());
}

unsafe fn handle_signal(sig: c_int, info: siginfo_t, void: c_void) {


    let signal = &Signal::try_from(sig).unwrap();
    let handler = {
        let handlers = SIGNAL_HANDLERS.lock().unwrap();
        let handler_holder = handlers.get(signal).unwrap();
        &mut **handler_holder.handler.get()
    };
    handler.handle(*signal, info, void);
}

pub unsafe fn setup_signal_handler<T: 'static + Handler>(handler: &mut T) -> Result<(), Error> {
    // First, set up our own stack to be used during segfault handling. (and specify `SA_ONSTACK` in `sigaction`)
    if SIGNAL_STACK_PTR.is_null() {
        SIGNAL_STACK_PTR = malloc(SIGNAL_STACK_SIZE);

        if SIGNAL_STACK_PTR.is_null() {
            panic!(
                "Failed to allocate signal stack with {} bytes!",
                SIGNAL_STACK_SIZE
            );
        }
    }
    let mut ss: stack_t = mem::zeroed();
    ss.ss_size = SIGNAL_STACK_SIZE;
    ss.ss_sp = SIGNAL_STACK_PTR;
    sigaltstack(&mut ss as *mut stack_t, ptr::null_mut() as _);

    let mut sa: sigaction = mem::zeroed();
    sigemptyset(&mut sa.sa_mask as *mut libc::sigset_t);
    sa.sa_flags = SA_NODEFER | SA_SIGINFO | SA_ONSTACK;
    sa.sa_sigaction = handle_signal as usize;
    let signals = handler.signals();
    for sig in signals {
        SIGNAL_HANDLERS.lock().unwrap().insert(sig, HandlerHolder {
            handler: UnsafeCell::new(handler as *mut dyn Handler),
        });

        if sigaction(sig as i32, &mut sa as *mut sigaction, ptr::null_mut()) < 0 {
            panic!("Could not set up {} handler", sig);
        }
    }

    Ok(())
}
