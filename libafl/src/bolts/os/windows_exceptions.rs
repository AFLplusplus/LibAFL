//! Exception handling for Windows

pub use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_POINTERS,
};

pub use windows::Win32::Foundation::NTSTATUS;

use crate::Error;
use std::os::raw::{c_long, c_void};

use alloc::vec::Vec;
use core::{
    cell::UnsafeCell,
    fmt::{self, Display, Formatter},
    ptr,
    ptr::write_volatile,
    sync::atomic::{compiler_fence, Ordering},
};

use num_enum::TryFromPrimitive;

//const EXCEPTION_CONTINUE_EXECUTION: c_long = -1;
//const EXCEPTION_CONTINUE_SEARCH: c_long = 0;
const EXCEPTION_EXECUTE_HANDLER: c_long = 1;

// From https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-headers/crt/signal.h
pub const SIGINT: i32 = 2;
pub const SIGILL: i32 = 4;
pub const SIGABRT_COMPAT: i32 = 6;
pub const SIGFPE: i32 = 8;
pub const SIGSEGV: i32 = 11;
pub const SIGTERM: i32 = 15;
pub const SIGBREAK: i32 = 21;
pub const SIGABRT: i32 = 22;
pub const SIGABRT2: i32 = 22;

// From https://github.com/wine-mirror/wine/blob/master/include/winnt.h#L611
pub const STATUS_WAIT_0: u32 = 0x00000000;
pub const STATUS_ABANDONED_WAIT_0: u32 = 0x00000080;
pub const STATUS_USER_APC: u32 = 0x000000C0;
pub const STATUS_TIMEOUT: u32 = 0x00000102;
pub const STATUS_PENDING: u32 = 0x00000103;
pub const STATUS_SEGMENT_NOTIFICATION: u32 = 0x40000005;
pub const STATUS_FATAL_APP_EXIT: u32 = 0x40000015;
pub const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x80000001;
pub const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x80000002;
pub const STATUS_BREAKPOINT: u32 = 0x80000003;
pub const STATUS_SINGLE_STEP: u32 = 0x80000004;
pub const STATUS_LONGJUMP: u32 = 0x80000026;
pub const STATUS_UNWIND_CONSOLIDATE: u32 = 0x80000029;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC0000005;
pub const STATUS_IN_PAGE_ERROR: u32 = 0xC0000006;
pub const STATUS_INVALID_HANDLE: u32 = 0xC0000008;
pub const STATUS_NO_MEMORY: u32 = 0xC0000017;
pub const STATUS_ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
pub const STATUS_NONCONTINUABLE_EXCEPTION: u32 = 0xC0000025;
pub const STATUS_INVALID_DISPOSITION: u32 = 0xC0000026;
pub const STATUS_ARRAY_BOUNDS_EXCEEDED: u32 = 0xC000008C;
pub const STATUS_FLOAT_DENORMAL_OPERAND: u32 = 0xC000008D;
pub const STATUS_FLOAT_DIVIDE_BY_ZERO: u32 = 0xC000008E;
pub const STATUS_FLOAT_INEXACT_RESULT: u32 = 0xC000008F;
pub const STATUS_FLOAT_INVALID_OPERATION: u32 = 0xC0000090;
pub const STATUS_FLOAT_OVERFLOW: u32 = 0xC0000091;
pub const STATUS_FLOAT_STACK_CHECK: u32 = 0xC0000092;
pub const STATUS_FLOAT_UNDERFLOW: u32 = 0xC0000093;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: u32 = 0xC0000094;
pub const STATUS_INTEGER_OVERFLOW: u32 = 0xC0000095;
pub const STATUS_PRIVILEGED_INSTRUCTION: u32 = 0xC0000096;
pub const STATUS_STACK_OVERFLOW: u32 = 0xC00000FD;
pub const STATUS_DLL_NOT_FOUND: u32 = 0xC0000135;
pub const STATUS_ORDINAL_NOT_FOUND: u32 = 0xC0000138;
pub const STATUS_ENTRYPOINT_NOT_FOUND: u32 = 0xC0000139;
pub const STATUS_CONTROL_C_EXIT: u32 = 0xC000013A;
pub const STATUS_DLL_INIT_FAILED: u32 = 0xC0000142;
pub const STATUS_FLOAT_MULTIPLE_FAULTS: u32 = 0xC00002B4;
pub const STATUS_FLOAT_MULTIPLE_TRAPS: u32 = 0xC00002B5;
pub const STATUS_REG_NAT_CONSUMPTION: u32 = 0xC00002C9;
pub const STATUS_HEAP_CORRUPTION: u32 = 0xC0000374;
pub const STATUS_STACK_BUFFER_OVERRUN: u32 = 0xC0000409;
pub const STATUS_INVALID_CRUNTIME_PARAMETER: u32 = 0xC0000417;
pub const STATUS_ASSERTION_FAILURE: u32 = 0xC0000420;
pub const STATUS_SXS_EARLY_DEACTIVATION: u32 = 0xC015000F;
pub const STATUS_SXS_INVALID_DEACTIVATION: u32 = 0xC0150010;

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u32)]
pub enum ExceptionCode {
    // From https://docs.microsoft.com/en-us/windows/win32/debug/getexceptioncode
    AccessViolation = STATUS_ACCESS_VIOLATION,
    ArrayBoundsExceeded = STATUS_ARRAY_BOUNDS_EXCEEDED,
    Breakpoint = STATUS_BREAKPOINT,
    DatatypeMisalignment = STATUS_DATATYPE_MISALIGNMENT,
    FltDenormalOperand = STATUS_FLOAT_DENORMAL_OPERAND,
    FltDivideByZero = STATUS_FLOAT_DIVIDE_BY_ZERO,
    FltInexactResult = STATUS_FLOAT_INEXACT_RESULT,
    FltInvalidOperation = STATUS_FLOAT_INVALID_OPERATION,
    FltOverflow = STATUS_FLOAT_OVERFLOW,
    FltStackCheck = STATUS_FLOAT_STACK_CHECK,
    FltUnderflow = STATUS_FLOAT_UNDERFLOW,
    GuardPageViolation = STATUS_GUARD_PAGE_VIOLATION,
    IllegalInstruction = STATUS_ILLEGAL_INSTRUCTION,
    InPageError = STATUS_IN_PAGE_ERROR,
    IntegerDivideByZero = STATUS_INTEGER_DIVIDE_BY_ZERO,
    IntegerOverflow = STATUS_INTEGER_OVERFLOW,
    InvalidDisposition = STATUS_INVALID_DISPOSITION,
    InvalidHandle = STATUS_INVALID_HANDLE,
    NoncontinuableException = STATUS_NONCONTINUABLE_EXCEPTION,
    PrivilegedInstruction = STATUS_PRIVILEGED_INSTRUCTION,
    SingleStep = STATUS_SINGLE_STEP,
    StackOverflow = STATUS_STACK_OVERFLOW,
    UnwindConsolidate = STATUS_UNWIND_CONSOLIDATE,
    // Addition exceptions
    Wait0 = STATUS_WAIT_0,
    AbandonedWait0 = STATUS_ABANDONED_WAIT_0,
    UserAPC = STATUS_USER_APC,
    Timeout = STATUS_TIMEOUT,
    Pending = STATUS_PENDING,
    SegmentNotification = STATUS_SEGMENT_NOTIFICATION,
    FatalAppExit = STATUS_FATAL_APP_EXIT,
    Longjump = STATUS_LONGJUMP,
    DLLNotFound = STATUS_DLL_NOT_FOUND,
    OrdinalNotFound = STATUS_ORDINAL_NOT_FOUND,
    EntryPointNotFound = STATUS_ENTRYPOINT_NOT_FOUND,
    ControlCExit = STATUS_CONTROL_C_EXIT,
    DllInitFailed = STATUS_DLL_INIT_FAILED,
    FltMultipleFaults = STATUS_FLOAT_MULTIPLE_FAULTS,
    FltMultipleTraps = STATUS_FLOAT_MULTIPLE_TRAPS,
    RegNatConsumption = STATUS_REG_NAT_CONSUMPTION,
    HeapCorruption = STATUS_HEAP_CORRUPTION,
    StackBufferOverrun = STATUS_STACK_BUFFER_OVERRUN,
    InvalidCRuntimeParameter = STATUS_INVALID_CRUNTIME_PARAMETER,
    AssertionFailure = STATUS_ASSERTION_FAILURE,
    SXSEarlyDeactivation = STATUS_SXS_EARLY_DEACTIVATION,
    SXSInvalidDeactivation = STATUS_SXS_INVALID_DEACTIVATION,
    #[num_enum(default)]
    Other,
}

pub static CRASH_EXCEPTIONS: &[ExceptionCode] = &[
    ExceptionCode::AccessViolation,
    ExceptionCode::ArrayBoundsExceeded,
    ExceptionCode::FltDivideByZero,
    ExceptionCode::GuardPageViolation,
    ExceptionCode::IllegalInstruction,
    ExceptionCode::InPageError,
    ExceptionCode::IntegerDivideByZero,
    ExceptionCode::InvalidHandle,
    ExceptionCode::NoncontinuableException,
    ExceptionCode::PrivilegedInstruction,
    ExceptionCode::StackOverflow,
    ExceptionCode::HeapCorruption,
    ExceptionCode::StackBufferOverrun,
    ExceptionCode::AssertionFailure,
    ExceptionCode::Other,
];

impl PartialEq for ExceptionCode {
    fn eq(&self, other: &Self) -> bool {
        *self as u32 == *other as u32
    }
}

impl Eq for ExceptionCode {}

unsafe impl Sync for ExceptionCode {}

impl Display for ExceptionCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ExceptionCode::AccessViolation => write!(f, "STATUS_ACCESS_VIOLATION")?,
            ExceptionCode::ArrayBoundsExceeded => write!(f, "STATUS_ARRAY_BOUNDS_EXCEEDED")?,
            ExceptionCode::Breakpoint => write!(f, "STATUS_BREAKPOINT")?,
            ExceptionCode::DatatypeMisalignment => write!(f, "STATUS_DATATYPE_MISALIGNMENT")?,
            ExceptionCode::FltDenormalOperand => write!(f, "STATUS_FLOAT_DENORMAL_OPERAND")?,
            ExceptionCode::FltDivideByZero => write!(f, "STATUS_FLOAT_DIVIDE_BY_ZERO")?,
            ExceptionCode::FltInexactResult => write!(f, "STATUS_FLOAT_INEXACT_RESULT")?,
            ExceptionCode::FltInvalidOperation => write!(f, "STATUS_FLOAT_INVALID_OPERATION")?,
            ExceptionCode::FltOverflow => write!(f, "STATUS_FLOAT_OVERFLOW")?,
            ExceptionCode::FltStackCheck => write!(f, "STATUS_FLOAT_STACK_CHECK")?,
            ExceptionCode::FltUnderflow => write!(f, "STATUS_FLOAT_UNDERFLOW")?,
            ExceptionCode::GuardPageViolation => write!(f, "STATUS_GUARD_PAGE_VIOLATION")?,
            ExceptionCode::IllegalInstruction => write!(f, "STATUS_ILLEGAL_INSTRUCTION")?,
            ExceptionCode::InPageError => write!(f, "STATUS_IN_PAGE_ERROR")?,
            ExceptionCode::IntegerDivideByZero => write!(f, "STATUS_INTEGER_DIVIDE_BY_ZERO")?,
            ExceptionCode::IntegerOverflow => write!(f, "STATUS_INTEGER_OVERFLOW")?,
            ExceptionCode::InvalidDisposition => write!(f, "STATUS_INVALID_DISPOSITION")?,
            ExceptionCode::InvalidHandle => write!(f, "STATUS_INVALID_HANDLE")?,
            ExceptionCode::NoncontinuableException => write!(f, "STATUS_NONCONTINUABLE_EXCEPTION")?,
            ExceptionCode::PrivilegedInstruction => write!(f, "STATUS_PRIVILEGED_INSTRUCTION")?,
            ExceptionCode::SingleStep => write!(f, "STATUS_SINGLE_STEP")?,
            ExceptionCode::StackOverflow => write!(f, "STATUS_STACK_OVERFLOW")?,
            ExceptionCode::UnwindConsolidate => write!(f, "STATUS_UNWIND_CONSOLIDATE")?,
            ExceptionCode::Wait0 => write!(f, "STATUS_WAIT_0")?,
            ExceptionCode::AbandonedWait0 => write!(f, "STATUS_ABANDONED_WAIT_0")?,
            ExceptionCode::UserAPC => write!(f, "STATUS_USER_APC")?,
            ExceptionCode::Timeout => write!(f, "STATUS_TIMEOUT")?,
            ExceptionCode::Pending => write!(f, "STATUS_PENDING")?,
            ExceptionCode::SegmentNotification => write!(f, "STATUS_SEGMENT_NOTIFICATION")?,
            ExceptionCode::FatalAppExit => write!(f, "STATUS_FATAL_APP_EXIT")?,
            ExceptionCode::Longjump => write!(f, "STATUS_LONGJUMP")?,
            ExceptionCode::DLLNotFound => write!(f, "STATUS_DLL_NOT_FOUND")?,
            ExceptionCode::OrdinalNotFound => write!(f, "STATUS_ORDINAL_NOT_FOUND")?,
            ExceptionCode::EntryPointNotFound => write!(f, "STATUS_ENTRYPOINT_NOT_FOUND")?,
            ExceptionCode::ControlCExit => write!(f, "STATUS_CONTROL_C_EXIT")?,
            ExceptionCode::DllInitFailed => write!(f, "STATUS_DLL_INIT_FAILED")?,
            ExceptionCode::FltMultipleFaults => write!(f, "STATUS_FLOAT_MULTIPLE_FAULTS")?,
            ExceptionCode::FltMultipleTraps => write!(f, "STATUS_FLOAT_MULTIPLE_TRAPS")?,
            ExceptionCode::RegNatConsumption => write!(f, "STATUS_REG_NAT_CONSUMPTION")?,
            ExceptionCode::HeapCorruption => write!(f, "STATUS_HEAP_CORRUPTION")?,
            ExceptionCode::StackBufferOverrun => write!(f, "STATUS_STACK_BUFFER_OVERRUN")?,
            ExceptionCode::InvalidCRuntimeParameter => {
                write!(f, "STATUS_INVALID_CRUNTIME_PARAMETER")?;
            }
            ExceptionCode::AssertionFailure => write!(f, "STATUS_ASSERTION_FAILURE")?,
            ExceptionCode::SXSEarlyDeactivation => write!(f, "STATUS_SXS_EARLY_DEACTIVATION")?,
            ExceptionCode::SXSInvalidDeactivation => write!(f, "STATUS_SXS_INVALID_DEACTIVATION")?,
            ExceptionCode::Other => write!(f, "Other/User defined exception")?,
        };

        Ok(())
    }
}

pub static EXCEPTION_CODES_MAPPING: [ExceptionCode; 46] = [
    ExceptionCode::AccessViolation,
    ExceptionCode::ArrayBoundsExceeded,
    ExceptionCode::Breakpoint,
    ExceptionCode::DatatypeMisalignment,
    ExceptionCode::FltDenormalOperand,
    ExceptionCode::FltDivideByZero,
    ExceptionCode::FltInexactResult,
    ExceptionCode::FltInvalidOperation,
    ExceptionCode::FltOverflow,
    ExceptionCode::FltStackCheck,
    ExceptionCode::FltUnderflow,
    ExceptionCode::GuardPageViolation,
    ExceptionCode::IllegalInstruction,
    ExceptionCode::InPageError,
    ExceptionCode::IntegerDivideByZero,
    ExceptionCode::IntegerOverflow,
    ExceptionCode::InvalidDisposition,
    ExceptionCode::InvalidHandle,
    ExceptionCode::NoncontinuableException,
    ExceptionCode::PrivilegedInstruction,
    ExceptionCode::SingleStep,
    ExceptionCode::StackOverflow,
    ExceptionCode::UnwindConsolidate,
    ExceptionCode::Wait0,
    ExceptionCode::AbandonedWait0,
    ExceptionCode::UserAPC,
    ExceptionCode::Timeout,
    ExceptionCode::Pending,
    ExceptionCode::SegmentNotification,
    ExceptionCode::FatalAppExit,
    ExceptionCode::Longjump,
    ExceptionCode::DLLNotFound,
    ExceptionCode::OrdinalNotFound,
    ExceptionCode::EntryPointNotFound,
    ExceptionCode::ControlCExit,
    ExceptionCode::DllInitFailed,
    ExceptionCode::FltMultipleFaults,
    ExceptionCode::FltMultipleTraps,
    ExceptionCode::RegNatConsumption,
    ExceptionCode::HeapCorruption,
    ExceptionCode::StackBufferOverrun,
    ExceptionCode::InvalidCRuntimeParameter,
    ExceptionCode::AssertionFailure,
    ExceptionCode::SXSEarlyDeactivation,
    ExceptionCode::SXSInvalidDeactivation,
    ExceptionCode::Other,
];

pub trait Handler {
    /// Handle an exception
    fn handle(
        &mut self,
        exception_code: ExceptionCode,
        exception_pointers: *mut EXCEPTION_POINTERS,
    );
    /// Return a list of exceptions to handle
    fn exceptions(&self) -> Vec<ExceptionCode>;
}

struct HandlerHolder {
    handler: UnsafeCell<*mut dyn Handler>,
}

unsafe impl Send for HandlerHolder {}

/// Keep track of which handler is registered for which exception
static mut EXCEPTION_HANDLERS: [Option<HandlerHolder>; 64] = [
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
];

unsafe fn internal_handle_exception(
    exception_code: ExceptionCode,
    exception_pointers: *mut EXCEPTION_POINTERS,
) -> i32 {
    let index = EXCEPTION_CODES_MAPPING
        .iter()
        .position(|x| *x == exception_code)
        .unwrap();
    match &EXCEPTION_HANDLERS[index] {
        Some(handler_holder) => {
            let handler = &mut **handler_holder.handler.get();
            handler.handle(exception_code, exception_pointers);
            EXCEPTION_EXECUTE_HANDLER
        }
        None => EXCEPTION_EXECUTE_HANDLER,
    }
}

/// Internal function that is being called whenever an exception arrives (stdcall).
unsafe extern "system" fn handle_exception(exception_pointers: *mut EXCEPTION_POINTERS) -> c_long {
    let code = exception_pointers
        .as_mut()
        .unwrap()
        .ExceptionRecord
        .as_mut()
        .unwrap()
        .ExceptionCode;
    let exception_code = ExceptionCode::try_from(code.0).unwrap();
    // println!("Received {}", exception_code);
    internal_handle_exception(exception_code, exception_pointers)
}

type NativeSignalHandlerType = unsafe extern "C" fn(i32);
extern "C" {
    fn signal(signum: i32, func: NativeSignalHandlerType) -> *const c_void;
}

unsafe extern "C" fn handle_signal(_signum: i32) {
    // println!("Received signal {}", _signum);
    internal_handle_exception(ExceptionCode::AssertionFailure, ptr::null_mut());
}

/// Setup Win32 exception handlers in a somewhat rusty way.
/// # Safety
/// Exception handlers are usually ugly, handle with care!
pub unsafe fn setup_exception_handler<T: 'static + Handler>(handler: &mut T) -> Result<(), Error> {
    let exceptions = handler.exceptions();
    let mut catch_assertions = false;
    for exception_code in exceptions {
        if exception_code == ExceptionCode::AssertionFailure {
            catch_assertions = true;
        }
        let index = EXCEPTION_CODES_MAPPING
            .iter()
            .position(|x| *x == exception_code)
            .unwrap();
        write_volatile(
            &mut EXCEPTION_HANDLERS[index],
            Some(HandlerHolder {
                handler: UnsafeCell::new(handler as *mut dyn Handler),
            }),
        );
    }
    compiler_fence(Ordering::SeqCst);
    if catch_assertions {
        signal(SIGABRT, handle_signal);
    }
    // SetUnhandledFilter does not work with frida since the stack is changed and exception handler is lost with Stalker enabled.
    // See https://github.com/AFLplusplus/LibAFL/pull/403
    AddVectoredExceptionHandler(
        1,
        Some(core::mem::transmute(handle_exception as *const c_void)),
    );
    Ok(())
}
