//! Signal handling for unix
#[cfg(feature = "std")]
use alloc::ffi::CString;
#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
use core::mem::size_of;
use core::{
    fmt::{self, Display, Formatter},
    mem,
};
#[cfg(feature = "alloc")]
use core::{
    ptr,
    sync::atomic::{AtomicPtr, Ordering},
};

use libafl_core::format;
/// armv7 `libc` does not feature a `uncontext_t` implementation
#[cfg(target_arch = "arm")]
pub use libc::c_ulong;
#[cfg(feature = "std")]
use nix::errno::Errno;

/// The special exit code when the target exited through ctrl-c
pub const CTRL_C_EXIT: i32 = 100;

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

/// User Context Struct on `arm` `linux`
#[cfg(all(target_os = "linux", target_arch = "arm"))]
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

/// # Internal representation
///
/// ```c
/// _STRUCT_ARM_EXCEPTION_STATE64
/// {
///    __uint64_t far;         /* Virtual Fault Address */
///    __uint32_t esr;         /* Exception syndrome */
///    __uint32_t exception;   /* number of arm exception taken */
/// };
/// ```
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[derive(Debug)]
#[repr(C)]
#[expect(clippy::pub_underscore_fields)]
#[allow(non_camel_case_types)] // expect breaks for some reason
pub struct arm_exception_state64 {
    /// Virtual Fault Address
    pub __far: u64,
    /// Exception syndrome
    pub __esr: u32,
    /// number of arm exception taken
    pub __exception: u32,
}

/// ```c
/// _STRUCT_ARM_THREAD_STATE64
/// {
/// __uint64_t __x[29]; /* General purpose registers x0-x28 */
/// __uint64_t __fp;    /* Frame pointer x29 */
/// __uint64_t __lr;    /* Link register x30 */
/// __uint64_t __sp;    /* Stack pointer x31 */
/// __uint64_t __pc;    /* Program counter */
/// __uint32_t __cpsr;  /* Current program status register */
/// __uint32_t __pad;   /* Same size for 32-bit or 64-bit clients */
/// };
/// ```
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[derive(Debug)]
#[repr(C)]
#[expect(clippy::pub_underscore_fields)]
#[allow(non_camel_case_types)] // expect breaks for some reason
pub struct arm_thread_state64 {
    /// General purpose registers x0-x28
    pub __x: [u64; 29],
    /// Frame pointer x29
    pub __fp: u64,
    /// Link register x30
    pub __lr: u64,
    /// Stack pointer x31
    pub __sp: u64,
    /// Program counter
    pub __pc: u64,
    /// Current program status register
    pub __cpsr: u32,
    /// Same size for 32-bit or 64-bit clients
    pub __pad: u32,
}

/// ```c
/// _STRUCT_ARM_NEON_STATE64
/// {
/// char opaque[(32 * 16) + (2 * sizeof(__uint32_t))];
/// } __attribute__((aligned(16)));
/// ````
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[derive(Debug)]
#[repr(C, align(16))]
#[allow(non_camel_case_types)] // expect breaks for some reason
pub struct arm_neon_state64 {
    /// opaque
    pub opaque: [u8; (32 * 16) + (2 * size_of::<u32>())],
}

/// ```c
/// _STRUCT_MCONTEXT64
/// {
///    _STRUCT_ARM_EXCEPTION_STATE64   es;
///    _STRUCT_ARM_THREAD_STATE64      ss;
///    _STRUCT_ARM_NEON_STATE64        ns;
/// };
/// ```
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[derive(Debug)]
#[repr(C)]
#[expect(clippy::pub_underscore_fields)]
#[allow(non_camel_case_types)] // expect breaks for some reason
pub struct mcontext64 {
    /// `_STRUCT_ARM_EXCEPTION_STATE64`
    pub __es: arm_exception_state64,
    /// `_STRUCT_ARM_THREAD_STATE64`
    pub __ss: arm_thread_state64,
    /// `_STRUCT_ARM_NEON_STATE64`
    pub __ns: arm_neon_state64,
}

/// ```c
/// _STRUCT_SIGALTSTACK
/// {
/// void            *ss_sp;         /* signal stack base */
/// __darwin_size_t ss_size;        /* signal stack length */
/// int             ss_flags;       /* SA_DISABLE and/or SA_ONSTACK */
/// };
/// ```
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[derive(Debug)]
#[repr(C)]
#[allow(non_camel_case_types)] // expect breaks for some reason
pub struct sigaltstack {
    /// signal stack base
    pub ss_sp: *mut c_void,
    /// signal stack length
    pub ss_size: libc::size_t,
    /// `SA_DISABLE` and/or `SA_ONSTACK`
    pub ss_flags: c_int,
}

/// User Context Struct on apple `aarch64`
///
/// ```c
/// _STRUCT_UCONTEXT
/// {
///    int                     uc_onstack;
///    __darwin_sigset_t       uc_sigmask;     /* signal mask used by this context */
///    _STRUCT_SIGALTSTACK     uc_stack;       /* stack used by this context */
///    _STRUCT_UCONTEXT        *uc_link;       /* pointer to resuming context */
///    __darwin_size_t         uc_mcsize;      /* size of the machine context passed in */
///    _STRUCT_MCONTEXT        *uc_mcontext;   /* pointer to machine specific context */
/// #ifdef _XOPEN_SOURCE
///    _STRUCT_MCONTEXT        __mcontext_data;
/// #endif /* _XOPEN_SOURCE */
/// };
/// ```
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[derive(Debug)]
#[repr(C)]
#[allow(non_camel_case_types)] // expect breaks for some reason
pub struct ucontext_t {
    /// onstack
    pub uc_onstack: c_int,
    /// signal mask used by this context
    pub uc_sigmask: u32,
    /// stack used by this context
    pub uc_stack: sigaltstack,
    /// pointer to resuming context
    pub uc_link: *mut c_void,
    /// size of the machine context passed in
    pub uc_mcsize: ssize_t,
    /// pointer to machine specific context
    pub uc_mcontext: *mut mcontext64,
    /// The mcontext data in multiple steps.
    pub mcontext_data: mcontext64,
}

use libafl_core::Error;
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
use libc::ssize_t;
#[cfg(not(any(
    all(target_os = "linux", target_arch = "arm"),
    all(target_vendor = "apple", target_arch = "aarch64")
)))]
pub use libc::ucontext_t;
#[cfg(feature = "alloc")]
use libc::{
    SA_NODEFER, SA_ONSTACK, SA_SIGINFO, free, malloc, sigaction, sigaddset, sigaltstack,
    sigemptyset, stack_t,
};
use libc::{
    SIGABRT, SIGALRM, SIGBUS, SIGFPE, SIGHUP, SIGILL, SIGINT, SIGKILL, SIGPIPE, SIGQUIT, SIGSEGV,
    SIGTERM, SIGTRAP, SIGUSR2, c_int,
};
pub use libc::{c_void, siginfo_t};
use num_enum::{IntoPrimitive, TryFromPrimitive};

unsafe extern "C" {
    /// The `libc` `getcontext`
    /// For some reason, it's not available on `MacOS`.
    fn getcontext(ucp: *mut ucontext_t) -> c_int;
}

/// All signals on this system, as `enum`.
#[derive(Debug, IntoPrimitive, TryFromPrimitive, Copy, Clone)]
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

#[cfg(feature = "std")]
impl Signal {
    /// Handle an incoming signal
    pub fn handle(&self) {
        match self {
            Signal::SigInterrupt | Signal::SigQuit | Signal::SigTerm => {
                std::process::exit(CTRL_C_EXIT)
            }
            _ => {}
        }
    }
}

impl TryFrom<&str> for Signal {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            "SIGABRT" => Signal::SigAbort,
            "SIGBUS" => Signal::SigBus,
            "SIGFPE" => Signal::SigFloatingPointException,
            "SIGILL" => Signal::SigIllegalInstruction,
            "SIGPIPE" => Signal::SigPipe,
            "SIGSEGV" => Signal::SigSegmentationFault,
            "SIGUSR2" => Signal::SigUser2,
            "SIGALRM" => Signal::SigAlarm,
            "SIGHUP" => Signal::SigHangUp,
            "SIGKILL" => Signal::SigKill,
            "SIGQUIT" => Signal::SigQuit,
            "SIGTERM" => Signal::SigTerm,
            "SIGINT" => Signal::SigInterrupt,
            "SIGTRAP" => Signal::SigTrap,
            _ => return Err(Error::illegal_argument(format!("No signal named {value}"))),
        })
    }
}

#[cfg(feature = "std")]
impl From<Signal> for nix::sys::signal::Signal {
    fn from(value: Signal) -> Self {
        // we can be semi-certain that all signals exist in nix.
        i32::from(value).try_into().unwrap()
    }
}

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
        }

        Ok(())
    }
}

/// A trait for `LibAFL` signal handling
#[cfg(feature = "alloc")]
pub trait SignalHandler {
    /// Handle a signal
    ///
    /// # Safety
    /// This is generally not safe to call. It should only be called through the signal it was registered for.
    /// Signal handling is hard, don't mess with it :).
    unsafe fn handle(
        &mut self,
        signal: Signal,
        info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
    );
    /// Return a list of signals to handle
    fn signals(&self) -> Vec<Signal>;
}

#[cfg(feature = "alloc")]
struct HandlerHolder(*mut dyn SignalHandler);

#[cfg(feature = "alloc")]
unsafe impl Send for HandlerHolder {}
#[cfg(feature = "alloc")]
unsafe impl Sync for HandlerHolder {}

/// Let's get 8 mb for now.
#[cfg(feature = "alloc")]
const SIGNAL_STACK_SIZE: usize = 2 << 22;

#[cfg(feature = "alloc")]
const MAX_SIGNALS: usize = 128;

/// Keep track of which handler is registered for which signal using atomic pointers.
#[cfg(feature = "alloc")]
static SIGNAL_HANDLERS: [AtomicPtr<HandlerHolder>; MAX_SIGNALS] =
    [const { AtomicPtr::new(ptr::null_mut()) }; MAX_SIGNALS];

#[cfg(feature = "alloc")]
struct ExitOnUnwind;

#[cfg(feature = "alloc")]
impl Drop for ExitOnUnwind {
    fn drop(&mut self) {
        const MSG: &[u8] = b"Signal handler panicked\n";
        // SAFETY: `write(2)` and `_exit(2)` are async-signal-safe; avoids allocator `free()`
        // and prevents `sigreturn` loops on synchronous hardware faults.
        unsafe {
            let _n = libc::write(libc::STDERR_FILENO, MSG.as_ptr().cast(), MSG.len());
            libc::_exit(101);
        }
    }
}

/// Internal C-ABI signal trampoline invoked whenever a registered signal arrives.
///
/// # Safety
/// Must only be invoked by the OS signal delivery mechanism (or with valid `siginfo_t` /
/// `ucontext_t` pointers) for signals configured via [`setup_signal_handler()`].
#[cfg(feature = "alloc")]
unsafe extern "C" fn handle_signal(sig: c_int, info: *mut siginfo_t, void: *mut c_void) {
    let unwind_guard = ExitOnUnwind;
    unsafe {
        if let Ok(signal) = Signal::try_from(sig)
            && (signal as usize) < MAX_SIGNALS
            && let Some(holder) = SIGNAL_HANDLERS[signal as usize]
                .load(Ordering::Acquire)
                .as_ref()
            && let Some(handler) = holder.0.as_mut()
        {
            let mut fallback_info: siginfo_t;
            let info_ref = if info.is_null() {
                fallback_info = mem::zeroed();
                &mut fallback_info
            } else if info.is_aligned() {
                &mut *info
            } else {
                fallback_info = ptr::read_unaligned(info);
                &mut fallback_info
            };
            let uctx_ptr = void.cast::<ucontext_t>();
            let uctx = if uctx_ptr.is_aligned() {
                uctx_ptr.as_mut()
            } else {
                None
            };
            handler.handle(signal, info_ref, uctx);
        }
    }
    mem::forget(unwind_guard);
}

/// Setup signal handlers in a somewhat rusty way.
///
/// This will allocate a signal stack and set the signal handlers accordingly.
/// It is, for example, used in `LibAFL's` `InProcessExecutor` to restart the fuzzer in case of a crash,
/// or to handle `SIGINT` in the broker process.
///
/// # Safety
/// `handler` must be non-null, aligned, and point to a valid `T` at a stable address for as long
/// as the signal handlers stay installed, without concurrent `&T`/`&mut T` aliasing. Because
/// `SA_NODEFER` permits reentrant delivery (and `siglongjmp`), `T` must be zero-sized or guarantee
/// `SignalHandler::handle` is never entered reentrantly or concurrently across threads.
#[cfg(feature = "alloc")]
pub unsafe fn setup_signal_handler<T: 'static + SignalHandler>(
    handler: *mut T,
) -> Result<(), Error> {
    if handler.is_null() || !handler.is_aligned() {
        return Err(Error::illegal_argument(
            "Signal handler pointer must be non-null and properly aligned",
        ));
    }
    unsafe {
        let signals = (*handler).signals();
        for &sig in &signals {
            let sig_idx = sig as usize;
            if sig_idx >= MAX_SIGNALS {
                return Err(Error::illegal_argument(format!(
                    "Signal number {sig_idx} exceeds MAX_SIGNALS ({MAX_SIGNALS})"
                )));
            }
        }

        let mut current_ss: stack_t = mem::zeroed();
        let needs_altstack = if sigaltstack(ptr::null(), &raw mut current_ss) == 0 {
            (current_ss.ss_flags & libc::SS_DISABLE) != 0 || current_ss.ss_size < SIGNAL_STACK_SIZE
        } else {
            true
        };
        if needs_altstack {
            let allocated = malloc(SIGNAL_STACK_SIZE);
            assert!(
                !allocated.is_null(),
                "Failed to allocate signal stack with {SIGNAL_STACK_SIZE} bytes!"
            );
            let mut ss: stack_t = mem::zeroed();
            ss.ss_size = SIGNAL_STACK_SIZE;
            ss.ss_sp = allocated;
            if sigaltstack(&raw const ss, ptr::null_mut()) < 0 {
                free(allocated);
            }
        }

        if !signals.is_empty() {
            let mut sa: sigaction = mem::zeroed();
            sigemptyset(&raw mut sa.sa_mask);
            sigaddset(&raw mut sa.sa_mask, SIGALRM);
            sa.sa_flags = SA_NODEFER | SA_SIGINFO | SA_ONSTACK;
            sa.sa_sigaction = handle_signal as *const () as usize;

            let shared_holder =
                Box::into_raw(Box::new(HandlerHolder(handler as *mut dyn SignalHandler)));
            let mut installed: Vec<(Signal, *mut HandlerHolder, sigaction)> =
                Vec::with_capacity(signals.len());
            for sig in signals {
                let sig_idx = sig as usize;
                let prev = SIGNAL_HANDLERS[sig_idx].swap(shared_holder, Ordering::AcqRel);
                let mut old_sa: sigaction = mem::zeroed();
                if sigaction(sig as i32, &raw const sa, &raw mut old_sa) < 0 {
                    #[cfg(feature = "std")]
                    if let Ok(err_str) = CString::new(format!("Failed to setup {sig} handler")) {
                        libc::perror(err_str.as_ptr());
                    }
                    SIGNAL_HANDLERS[sig_idx].store(prev, Ordering::Release);
                    for (s, old_ptr, prev_sa) in installed.into_iter().rev() {
                        sigaction(s as i32, &raw const prev_sa, ptr::null_mut());
                        SIGNAL_HANDLERS[s as usize].store(old_ptr, Ordering::Release);
                    }
                    return Err(Error::unknown(format!("Could not set up {sig} handler")));
                }
                installed.push((sig, prev, old_sa));
            }
        }

        Ok(())
    }
}

/// Function to get the current [`ucontext_t`] for this process.
///
/// This calls the libc `getcontext` function under the hood.
/// It can be useful, for example for `dump_regs`.
/// Note that calling this method may, of course, alter the state.
/// We wrap it here, as it seems to be (currently)
/// not available on `MacOS` in the `libc` crate.
#[cfg(unix)]
#[expect(clippy::inline_always)] // we assume that inlining will destroy less state
#[inline(always)]
pub fn ucontext() -> Result<ucontext_t, Error> {
    #[cfg(all(target_vendor = "apple", target_arch = "x86_64"))]
    {
        // `libc::ucontext_t` on `x86_64` Apple omits trailing `__mcontext_data` (712 B) that
        // `getcontext` populates directly after `uc_mcontext`.
        #[repr(C)]
        struct FullUcontext {
            uc: ucontext_t,
            mcontext_data: libc::__darwin_mcontext64,
        }
        static ZERO_MCTX: libc::__darwin_mcontext64 = unsafe { mem::zeroed() };
        let mut full = unsafe { mem::zeroed::<FullUcontext>() };
        return if unsafe { getcontext(&raw mut full.uc) } == 0 {
            full.uc.uc_mcontext = (&raw const ZERO_MCTX).cast_mut();
            Ok(full.uc)
        } else {
            ucontext_err()
        };
    }

    #[cfg(not(all(target_vendor = "apple", target_arch = "x86_64")))]
    {
        let mut ucontext = unsafe { mem::zeroed::<ucontext_t>() };
        if cfg!(not(any(target_os = "openbsd", target_os = "haiku"))) {
            if unsafe { getcontext(&raw mut ucontext) } == 0 {
                #[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
                {
                    static ZERO_MCTX: mcontext64 = unsafe { mem::zeroed() };
                    ucontext.uc_mcontext = (&raw const ZERO_MCTX).cast_mut();
                }
                Ok(ucontext)
            } else {
                ucontext_err()
            }
        } else {
            Ok(ucontext)
        }
    }
}

#[cfg(unix)]
#[cold]
fn ucontext_err() -> Result<ucontext_t, Error> {
    #[cfg(not(feature = "std"))]
    {
        unsafe { libc::perror(c"Failed to get ucontext".as_ptr()) };
        Err(Error::unknown("Failed to get ucontext"))
    }
    #[cfg(feature = "std")]
    Err(Error::unknown(format!(
        "Failed to get ucontext: {:?}",
        Errno::last()
    )))
}

#[cfg(all(test, unix, feature = "std"))]
mod tests {
    use core::{
        ptr::{self, NonNull},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::{
        Signal, SignalHandler, handle_signal, setup_signal_handler, siginfo_t, ucontext_t,
    };

    static TEST_CALLS: AtomicUsize = AtomicUsize::new(0);

    struct ZstSignalHandler;

    impl SignalHandler for ZstSignalHandler {
        unsafe fn handle(
            &mut self,
            signal: Signal,
            _info: &mut siginfo_t,
            _context: Option<&mut ucontext_t>,
        ) {
            if signal == Signal::SigUser2 && TEST_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
                unsafe {
                    handle_signal(Signal::SigAlarm as i32, ptr::null_mut(), ptr::null_mut());
                }
            } else {
                TEST_CALLS.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn signals(&self) -> alloc::vec::Vec<Signal> {
            alloc::vec![Signal::SigUser2, Signal::SigAlarm]
        }
    }

    #[test]
    fn test_signal_trampoline() {
        TEST_CALLS.store(0, Ordering::SeqCst);
        assert!(unsafe { setup_signal_handler(ptr::null_mut::<ZstSignalHandler>()) }.is_err());

        unsafe {
            handle_signal(9999, ptr::null_mut(), ptr::null_mut());
            handle_signal(Signal::SigUser2 as i32, ptr::null_mut(), ptr::null_mut());

            let handler_ptr = NonNull::<ZstSignalHandler>::dangling().as_ptr();
            #[cfg(not(miri))]
            setup_signal_handler(handler_ptr).unwrap();
            #[cfg(miri)]
            {
                let holder = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(
                    super::HandlerHolder(handler_ptr as *mut dyn SignalHandler),
                ));
                for sig in [Signal::SigUser2, Signal::SigAlarm] {
                    super::SIGNAL_HANDLERS[sig as usize].store(holder, Ordering::Release);
                }
            }
            let mut unaligned = [0u8; size_of::<siginfo_t>() + 1];
            handle_signal(
                Signal::SigUser2 as i32,
                unaligned.as_mut_ptr().add(1).cast::<siginfo_t>(),
                ptr::null_mut(),
            );
            #[cfg(miri)]
            {
                let holder = super::SIGNAL_HANDLERS[Signal::SigUser2 as usize]
                    .swap(ptr::null_mut(), Ordering::AcqRel);
                super::SIGNAL_HANDLERS[Signal::SigAlarm as usize]
                    .store(ptr::null_mut(), Ordering::Release);
                drop(alloc::boxed::Box::from_raw(holder));
            }
        }
        assert_eq!(TEST_CALLS.load(Ordering::SeqCst), 2);
        #[cfg(not(miri))]
        let _uctx = super::ucontext().unwrap();
    }
}
