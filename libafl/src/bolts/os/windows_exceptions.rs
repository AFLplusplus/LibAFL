use crate::{
    bolts::bindings::windows::win32::debug::{SetUnhandledExceptionFilter, EXCEPTION_POINTERS},
    Error,
};

use alloc::vec::Vec;
use core::{
    cell::UnsafeCell,
    convert::TryFrom,
    fmt::{self, Display, Formatter},
    mem, ptr,
    ptr::write_volatile,
    sync::atomic::{compiler_fence, Ordering},
};
use std::os::raw::{c_long, c_void};

use num_enum::{IntoPrimitive, TryFromPrimitive};

const EXCEPTION_CONTINUE_EXECUTION: c_long = -1;
//const EXCEPTION_CONTINUE_SEARCH: c_long = 0;
const EXCEPTION_EXECUTE_HANDLER: c_long = 1;

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

/// From https://docs.microsoft.com/en-us/windows/win32/debug/getexceptioncode
#[derive(IntoPrimitive, TryFromPrimitive, Clone, Copy)]
#[repr(u32)]
pub enum ExceptionCode {
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
        };

        Ok(())
    }
}

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
static mut EXCEPTION_HANDLERS: [Option<HandlerHolder>; 32] = [
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
];

type NativeHandlerType = extern "system" fn(*mut EXCEPTION_POINTERS) -> c_long;
static mut PREVIOUS_HANDLER: Option<NativeHandlerType> = None;

/// Internal function that is being called whenever an exception arrives (stdcall).
unsafe extern "system" fn handle_exception(exception_pointers: *mut EXCEPTION_POINTERS) -> c_long {
    let code = exception_pointers
        .as_mut()
        .unwrap()
        .exception_record
        .as_mut()
        .unwrap()
        .exception_code;
    let ret = match &EXCEPTION_HANDLERS[code as usize] {
        Some(handler_holder) => {
            let handler = &mut **handler_holder.handler.get();
            handler.handle(ExceptionCode::try_from(code).unwrap(), exception_pointers);
            EXCEPTION_EXECUTE_HANDLER
        }
        None => EXCEPTION_CONTINUE_EXECUTION,
    };
    if let Some(prev_handler) = unsafe { PREVIOUS_HANDLER } {
        prev_handler(exception_pointers)
    } else {
        ret
    }
}

/// Setup Win32 exception handlers in a somewhat rusty way.
pub unsafe fn setup_exception_handler<T: 'static + Handler>(handler: &mut T) -> Result<(), Error> {
    let exceptions = handler.exceptions();
    for code in exceptions {
        write_volatile(
            &mut EXCEPTION_HANDLERS[code as usize],
            Some(HandlerHolder {
                handler: UnsafeCell::new(handler as *mut dyn Handler),
            }),
        );
    }
    compiler_fence(Ordering::SeqCst);

    unsafe {
        if let Some(prev) = SetUnhandledExceptionFilter(Some(core::mem::transmute(handle_exception as as *const c_void))) {
            PREVIOUS_HANDLER = Some(core::mem::transmute(prev as *const c_void));
        }
    }
    Ok(())
}
