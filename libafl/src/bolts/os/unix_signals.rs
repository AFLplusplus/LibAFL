//! Signal handling for unix
use alloc::vec::Vec;
use core::{
    cell::UnsafeCell,
    fmt::{self, Display, Formatter},
    mem, ptr,
    ptr::{addr_of_mut, write_volatile},
    sync::atomic::{compiler_fence, Ordering},
};

#[cfg(feature = "std")]
use nix::errno::{errno, Errno};
#[cfg(feature = "std")]
use std::ffi::CString;

/// armv7 `libc` does not feature a `uncontext_t` implementation
#[cfg(target_arch = "arm")]
pub use libc::c_ulong;

/// ARMv7-specific representation of a saved context
#[cfg(target_arch = "arm")]
#[derive(Debug)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct mcontext_t {
    /// Signal Number
    pub trap_no: c_ulong,
    /// Error Code
    pub error_code: c_ulong,
    /// Old signal mask
    pub oldmask: c_ulong,
    /// GPR R0
    pub arm_r0: c_ulong,
    /// GPR R1
    pub arm_r1: c_ulong,
    /// GPR R2
    pub arm_r2: c_ulong,
    /// GPR R3
    pub arm_r3: c_ulong,
    /// GPR R4
    pub arm_r4: c_ulong,
    /// GPR R5
    pub arm_r5: c_ulong,
    /// GPR R6
    pub arm_r6: c_ulong,
    /// GPR R7
    pub arm_r7: c_ulong,
    /// GPR R8
    pub arm_r8: c_ulong,
    /// GPR R9
    pub arm_r9: c_ulong,
    /// GPR R10
    pub arm_r10: c_ulong,
    /// Frame Pointer
    pub arm_fp: c_ulong,
    /// Intra-Procedure Scratch Register
    pub arm_ip: c_ulong,
    /// Stack Pointer
    pub arm_sp: c_ulong,
    /// Link Register
    pub arm_lr: c_ulong,
    /// Program Counter
    pub arm_pc: c_ulong,
    /// Current Program Status Register
    pub arm_cpsr: c_ulong,
    /// Fault Address
    pub fault_address: c_ulong,
}

/// User Context Struct
#[cfg(target_arch = "arm")]
#[derive(Debug)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct ucontext_t {
    /// Flags
    pub uc_flags: u32,
    /// Pointer to the context that will be resumed when this context returns
    pub uc_link: *mut ucontext_t,
    /// Stack used by this context
    pub uc_stack: stack_t,
    /// Machine-specific representation of the saved context
    pub uc_mcontext: mcontext_t,
    /// Set of signals that are blocked when this context is active
    pub uc_sigmask: libc::sigset_t,
}

#[cfg(not(target_arch = "arm"))]
pub use libc::ucontext_t;

use libc::{
    c_int, malloc, sigaction, sigaddset, sigaltstack, sigemptyset, stack_t, SA_NODEFER, SA_ONSTACK,
    SA_SIGINFO, SIGABRT, SIGALRM, SIGBUS, SIGFPE, SIGHUP, SIGILL, SIGINT, SIGKILL, SIGPIPE,
    SIGQUIT, SIGSEGV, SIGTERM, SIGTRAP, SIGUSR2,
};
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::Error;

pub use libc::{c_void, siginfo_t};

extern "C" {
    fn getcontext(ucp: *mut ucontext_t) -> c_int;
}

/// All signals on this system, as `enum`.
#[derive(Debug, IntoPrimitive, TryFromPrimitive, Clone, Copy)]
#[repr(i32)]
pub enum Signal {
    /// `SIGABRT` signal id
    SigAbort = SIGABRT,
    /// `SIGBUS` signal id
    SigBus = SIGBUS,
    /// `SIGFPE` signal id
    SigFloatingPointException = SIGFPE,
    /// `SIGILL` signal id
    SigIllegalInstruction = SIGILL,
    /// `SIGPIPE` signal id
    SigPipe = SIGPIPE,
    /// `SIGSEGV` signal id
    SigSegmentationFault = SIGSEGV,
    /// `SIGUSR2` signal id
    SigUser2 = SIGUSR2,
    /// `SIGALARM` signal id
    SigAlarm = SIGALRM,
    /// `SIGHUP` signal id
    SigHangUp = SIGHUP,
    /// `SIGKILL` signal id
    SigKill = SIGKILL,
    /// `SIGQUIT` signal id
    SigQuit = SIGQUIT,
    /// `SIGTERM` signal id
    SigTerm = SIGTERM,
    /// `SIGINT` signal id
    SigInterrupt = SIGINT,
    /// `SIGTRAP` signal id
    SigTrap = SIGTRAP,
}

/// A list of crashing signals
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

/// A trait for `LibAFL` signal handling
pub trait Handler {
    /// Handle a signal
    fn handle(&mut self, signal: Signal, info: siginfo_t, _context: &mut ucontext_t);
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
/// unless the signal handlers registered using [`setup_signal_handler()`] are broken.
unsafe fn handle_signal(sig: c_int, info: siginfo_t, void: *mut c_void) {
    let signal = &Signal::try_from(sig).unwrap();
    let handler = {
        match &SIGNAL_HANDLERS[*signal as usize] {
            Some(handler_holder) => &mut **handler_holder.handler.get(),
            None => return,
        }
    };
    handler.handle(*signal, info, &mut *(void as *mut ucontext_t));
}

/// Setup signal handlers in a somewhat rusty way.
/// This will allocate a signal stack and set the signal handlers accordingly.
/// It is, for example, used in the [`type@crate::executors::InProcessExecutor`] to restart the fuzzer in case of a crash,
/// or to handle `SIGINT` in the broker process.
/// # Safety
/// The signal handlers will be called on any signal. They should (tm) be async safe.
/// A lot can go south in signal handling. Be sure you know what you are doing.
pub unsafe fn setup_signal_handler<T: 'static + Handler>(handler: &mut T) -> Result<(), Error> {
    // First, set up our own stack to be used during segfault handling. (and specify `SA_ONSTACK` in `sigaction`)
    if SIGNAL_STACK_PTR.is_null() {
        SIGNAL_STACK_PTR = malloc(SIGNAL_STACK_SIZE);

        // Rust always panics on OOM, so we will, too.
        assert!(
            !SIGNAL_STACK_PTR.is_null(),
            "Failed to allocate signal stack with {} bytes!",
            SIGNAL_STACK_SIZE
        );
    }
    let mut ss: stack_t = mem::zeroed();
    ss.ss_size = SIGNAL_STACK_SIZE;
    ss.ss_sp = SIGNAL_STACK_PTR;
    sigaltstack(addr_of_mut!(ss), ptr::null_mut() as _);

    let mut sa: sigaction = mem::zeroed();
    sigemptyset(addr_of_mut!(sa.sa_mask));
    sigaddset(addr_of_mut!(sa.sa_mask), SIGALRM);
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

        if sigaction(sig as i32, addr_of_mut!(sa), ptr::null_mut()) < 0 {
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

/// Function to get the current [`ucontext_t`] for this process.
/// This calls the libc `getcontext` function under the hood.
/// It can be useful, for example for `dump_regs`.
/// Note that calling this method may, of course, alter the state.
/// We wrap it here, as it seems to be (currently)
/// not available on `MacOS` in the `libc` crate.
#[cfg(unix)]
#[allow(clippy::inline_always)] // we assume that inlining will destroy less state
#[inline(always)]
pub fn ucontext() -> Result<ucontext_t, Error> {
    let mut ucontext = unsafe { mem::zeroed() };
    if unsafe { getcontext(&mut ucontext) } == 0 {
        Ok(ucontext)
    } else {
        #[cfg(not(feature = "std"))]
        unsafe {
            libc::perror(b"Failed to get ucontext\n".as_ptr() as _);
        };
        #[cfg(not(feature = "std"))]
        return Err(Error::Unknown("Failed to get ucontex".into()));

        #[cfg(feature = "std")]
        Err(Error::Unknown(format!(
            "Failed to get ucontext: {:?}",
            Errno::from_i32(errno())
        )))
    }
}
