//! Sanitizer Coverage comparison functions

#[cfg(feature = "sancov_cmplog")]
use core::{
    cmp,
    ffi::{c_char, c_int, c_void},
    sync::atomic::{AtomicU8, Ordering},
};

#[cfg(feature = "sancov_cmplog")]
use crate::{CMPLOG_ENABLED, CMPLOG_MAP_W, CMPLOG_RTN_LEN};

unsafe extern "C" {

    /// Trace an 8 bit `cmp`
    pub fn __sanitizer_cov_trace_cmp1(v0: u8, v1: u8);
    /// Trace a 16 bit `cmp`
    pub fn __sanitizer_cov_trace_cmp2(v0: u16, v1: u16);
    /// Trace a 32 bit `cmp`
    pub fn __sanitizer_cov_trace_cmp4(v0: u32, v1: u32);
    /// Trace a 64 bit `cmp`
    pub fn __sanitizer_cov_trace_cmp8(v0: u64, v1: u64);

    /// Trace an 8 bit constant `cmp`
    pub fn __sanitizer_cov_trace_const_cmp1(v0: u8, v1: u8);
    /// Trace a 16 bit constant `cmp`
    pub fn __sanitizer_cov_trace_const_cmp2(v0: u16, v1: u16);
    /// Trace a 32 bit constant `cmp`
    pub fn __sanitizer_cov_trace_const_cmp4(v0: u32, v1: u32);
    /// Trace a 64 bit constant `cmp`
    pub fn __sanitizer_cov_trace_const_cmp8(v0: u64, v1: u64);

    /// Trace a switch statement
    pub fn __sanitizer_cov_trace_switch(val: u64, cases: *const u64);
}

#[cfg(feature = "sancov_cmplog")]
#[inline]
fn cmplog_key(called_pc: *const c_void) -> usize {
    let k = called_pc as usize;
    ((k >> 4) ^ (k << 8)) & (CMPLOG_MAP_W - 1)
}

#[cfg(feature = "sancov_cmplog")]
#[inline]
fn cmplog_is_enabled() -> bool {
    unsafe { AtomicU8::from_ptr(&raw mut CMPLOG_ENABLED).load(Ordering::Relaxed) != 0 }
}

#[cfg(feature = "sancov_cmplog")]
#[inline]
unsafe fn log_strn(
    called_pc: *const c_void,
    s1: *const c_char,
    s2: *const c_char,
    n: usize,
    result: c_int,
) {
    if result != 0 && cmplog_is_enabled() {
        unsafe {
            crate::__libafl_targets_cmplog_routines_strn(
                cmplog_key(called_pc),
                s1.cast::<u8>(),
                s2.cast::<u8>(),
                cmp::min(n, CMPLOG_RTN_LEN),
            );
        }
    }
}

/// overriding `__sanitizer_weak_hook_memcmp`
/// # Safety
/// this function has raw pointer access
#[cfg(feature = "sancov_cmplog")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_weak_hook_memcmp(
    called_pc: *const c_void,
    s1: *const c_void,
    s2: *const c_void,
    n: usize,
    result: c_int,
) {
    if result != 0 && cmplog_is_enabled() {
        unsafe {
            crate::__libafl_targets_cmplog_routines_len(
                cmplog_key(called_pc),
                s1.cast::<u8>(),
                s2.cast::<u8>(),
                cmp::min(n, CMPLOG_RTN_LEN),
            );
        }
    }
}

/// overriding `__sanitizer_weak_hook_strncmp`
/// # Safety
/// this function has raw pointer access
#[cfg(feature = "sancov_cmplog")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_weak_hook_strncmp(
    called_pc: *const c_void,
    s1: *const c_char,
    s2: *const c_char,
    n: usize,
    result: c_int,
) {
    unsafe {
        log_strn(called_pc, s1, s2, n, result);
    }
}

/// overriding `__sanitizer_weak_hook_strncasecmp`
/// # Safety
/// this function has raw pointer access
#[cfg(feature = "sancov_cmplog")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_weak_hook_strncasecmp(
    called_pc: *const c_void,
    s1: *const c_char,
    s2: *const c_char,
    n: usize,
    result: c_int,
) {
    unsafe {
        log_strn(called_pc, s1, s2, n, result);
    }
}

/// overriding `__sanitizer_weak_hook_strcmp`
/// # Safety
/// this function has raw pointer access
#[cfg(feature = "sancov_cmplog")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_weak_hook_strcmp(
    called_pc: *const c_void,
    s1: *const c_char,
    s2: *const c_char,
    result: c_int,
) {
    unsafe {
        log_strn(called_pc, s1, s2, CMPLOG_RTN_LEN, result);
    }
}

/// overriding `__sanitizer_weak_hook_strcasecmp`
/// # Safety
/// this function has raw pointer access
#[cfg(feature = "sancov_cmplog")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_weak_hook_strcasecmp(
    called_pc: *const c_void,
    s1: *const c_char,
    s2: *const c_char,
    result: c_int,
) {
    unsafe {
        log_strn(called_pc, s1, s2, CMPLOG_RTN_LEN, result);
    }
}

#[cfg(all(test, unix, feature = "sancov_cmplog", not(miri)))]
mod tests {
    use core::{
        ffi::{c_char, c_void},
        ptr,
        sync::atomic::{AtomicU8, Ordering},
    };

    use libafl::observers::{CmpMap, CmpValues};
    use libafl_bolts::ToSlice;

    use super::{
        __sanitizer_weak_hook_memcmp, __sanitizer_weak_hook_strcasecmp,
        __sanitizer_weak_hook_strcmp, __sanitizer_weak_hook_strncasecmp,
        __sanitizer_weak_hook_strncmp, cmplog_key,
    };
    use crate::{
        CMPLOG_ENABLED,
        cmps::{CMPLOG_MAP_PTR, tests::lock_cmplog_test},
    };

    #[test]
    fn test_sancov_cmp_guard_page_and_magic_logging() {
        let _guard = lock_cmplog_test();
        unsafe {
            let page_size = usize::try_from(libc::sysconf(libc::_SC_PAGESIZE)).unwrap();
            let raw = libc::mmap(
                ptr::null_mut(),
                page_size * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(raw, libc::MAP_FAILED);
            assert_eq!(
                libc::mprotect(
                    raw.cast::<u8>().add(page_size).cast(),
                    page_size,
                    libc::PROT_NONE,
                ),
                0,
            );

            let map = CMPLOG_MAP_PTR;
            (*map).reset().unwrap();
            AtomicU8::from_ptr(&raw mut CMPLOG_ENABLED).store(1, Ordering::Relaxed);

            let s1 = raw.cast::<u8>().add(page_size - 1);
            let s2 = raw.cast::<u8>().add(page_size - 2);
            *s1 = b'X';
            *s2 = b'Y';
            let pc_guard = 0x1234usize as *const c_void;
            __sanitizer_weak_hook_strncmp(pc_guard, s1.cast::<c_char>(), s2.cast::<c_char>(), 32, -1);
            __sanitizer_weak_hook_strcmp(pc_guard, s1.cast::<c_char>(), s2.cast::<c_char>(), -1);
            __sanitizer_weak_hook_strncasecmp(
                pc_guard,
                s1.cast::<c_char>(),
                s2.cast::<c_char>(),
                32,
                -1,
            );
            __sanitizer_weak_hook_strcasecmp(pc_guard, s1.cast::<c_char>(), s2.cast::<c_char>(), -1);
            __sanitizer_weak_hook_memcmp(pc_guard, s1.cast(), s2.cast(), 32, -1);

            let pc_magic = 0x5678usize as *const c_void;
            __sanitizer_weak_hook_strcmp(pc_magic, c"AAAAAAAA".as_ptr(), c"DEADBEEF".as_ptr(), -1);

            AtomicU8::from_ptr(&raw mut CMPLOG_ENABLED).store(0, Ordering::Relaxed);

            let idx = cmplog_key(pc_magic);
            assert_eq!((*map).executions_for(idx), 1);
            let Some(CmpValues::Bytes((v0, v1))) = (*map).values_of(idx, 0) else {
                panic!("expected routine bytes");
            };
            assert_eq!(&v0.to_slice()[..8], b"AAAAAAAA");
            assert_eq!(&v1.to_slice()[..8], b"DEADBEEF");

            (*map).reset().unwrap();
            assert_eq!(libc::munmap(raw, page_size * 2), 0);
        }
    }
}
