//! Signal handling for unix
use alloc::vec::Vec;
use core::{
    cell::UnsafeCell,
    convert::TryFrom,
    fmt::{self, Display, Formatter},
    mem, ptr,
    ptr::write_volatile,
    sync::atomic::{compiler_fence, Ordering},
};

#[cfg(feature = "std")]
use std::ffi::CString;

use libc::{
    c_int, malloc, sigaction, sigaltstack, sigemptyset, stack_t, SA_NODEFER, SA_ONSTACK,
    SA_SIGINFO, SIGABRT, SIGALRM, SIGBUS, SIGFPE, SIGHUP, SIGILL, SIGINT, SIGKILL, SIGPIPE,
    SIGQUIT, SIGSEGV, SIGTERM, SIGTRAP, SIGUSR2,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::Error;

pub use libc::{c_void, siginfo_t};

#[derive(IntoPrimitive, TryFromPrimitive, Clone, Copy)]
#[repr(i32)]
#[allow(clippy::clippy::pub_enum_variant_names)]
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
    SigTrap = SIGTRAP,
}

pub static CRASH_SIGNALS: &[Signal] = &[
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
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Signal::SigAbort => write!(f, "SIGABRT")?,
            Signal::SigBus => write!(f, "SIGBUS")?,
            Signal::SigFloatingPointException => write!(f, "SIGFPE")?,
            Signal::SigIllegalInstruction => write!(f, "SIGILL")?,
            Signal::SigPipe => write!(f, "SIGPIPE")?,
            Signal::SigSegmentationFault => write!(f, "SIGSEGV")?,
            Signal::SigUser2 => write!(f, "SIGUSR2")?,
            Signal::SigAlarm => write!(f, "SIGALRM")?,
            Signal::SigHangUp => write!(f, "SIGHUP")?,
            Signal::SigKill => write!(f, "SIGKILL")?,
            Signal::SigQuit => write!(f, "SIGQUIT")?,
            Signal::SigTerm => write!(f, "SIGTERM")?,
            Signal::SigInterrupt => write!(f, "SIGINT")?,
            Signal::SigTrap => write!(f, "SIGTRAP")?,
        };

        Ok(())
    }
}

pub trait Handler {
    /// Handle a signal
    fn handle(&mut self, signal: Signal, info: siginfo_t, _void: *const c_void);
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

/// Keep track of which handler is registered for which signal
static mut SIGNAL_HANDLERS: [Option<HandlerHolder>; 32] = [
    // We cannot use [None; 32] because it requires Copy. Ugly, but I don't think there's an
    // alternative.
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
];

/// Internal function that is being called whenever a signal we are registered for arrives.
/// # Safety
/// This should be somewhat safe to call for signals previously registered,
/// unless the signal handlers registered using [setup_signal_handler] are broken.
unsafe fn handle_signal(sig: c_int, info: siginfo_t, void: *const c_void) {
    let signal = &Signal::try_from(sig).unwrap();
    let handler = {
        match &SIGNAL_HANDLERS[*signal as usize] {
            Some(handler_holder) => &mut **handler_holder.handler.get(),
            None => return,
        }
    };
    handler.handle(*signal, info, void);
}

/// Setup signal handlers in a somewhat rusty way.
/// This will allocate a signal stack and set the signal handlers accordingly.
/// It is, for example, used in the [crate::executors::InProcessExecutor] to restart the fuzzer in case of a crash,
/// or to handle `SIGINT` in the broker process.
/// # Safety
/// The signal handlers will be called on any signal. They should (tm) be async safe.
/// A lot can go south in signal handling. Be sure you know what you are doing.
pub unsafe fn setup_signal_handler<T: 'static + Handler>(handler: &mut T) -> Result<(), Error> {
    // First, set up our own stack to be used during segfault handling. (and specify `SA_ONSTACK` in `sigaction`)
    if SIGNAL_STACK_PTR.is_null() {
        SIGNAL_STACK_PTR = malloc(SIGNAL_STACK_SIZE);

        if SIGNAL_STACK_PTR.is_null() {
            // Rust always panics on OOM, so we will, too.
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
        write_volatile(
            &mut SIGNAL_HANDLERS[sig as usize],
            Some(HandlerHolder {
                handler: UnsafeCell::new(handler as *mut dyn Handler),
            }),
        );

        if sigaction(sig as i32, &mut sa as *mut sigaction, ptr::null_mut()) < 0 {
            #[cfg(feature = "std")]
            {
                let err_str = CString::new(format!("Failed to setup {} handler", sig)).unwrap();
                libc::perror(err_str.as_ptr());
            }
            return Err(Error::Unknown(format!("Could not set up {} handler", sig)));
        }
    }
    compiler_fence(Ordering::SeqCst);

    Ok(())
}
