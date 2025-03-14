//! # hooks
//!
//! This module provides the implementation of various functions implemented by
//! the standard C library which are used by applications. These functions are
//! are modified to provide the additional memory safety checks provided by
//! `asan`.
pub mod aligned_alloc;
pub mod atoi;
pub mod atol;
pub mod atoll;
pub mod bcmp;
pub mod bzero;
pub mod calloc;
pub mod explicit_bzero;
pub mod free;
pub mod malloc;
pub mod malloc_usable_size;
pub mod memalign;
pub mod memchr;
pub mod memcmp;
pub mod memcpy;
pub mod memmem;
pub mod memmove;
pub mod mempcpy;
pub mod memrchr;
pub mod memset;
pub mod mmap;
pub mod munmap;
pub mod posix_memalign;
pub mod pvalloc;
pub mod read;
pub mod realloc;
pub mod reallocarray;
pub mod stpcpy;
pub mod strcasecmp;
pub mod strcasestr;
pub mod strcat;
pub mod strchr;
pub mod strcmp;
pub mod strcpy;
pub mod strdup;
pub mod strlen;
pub mod strncasecmp;
pub mod strncmp;
pub mod strncpy;
pub mod strndup;
pub mod strnlen;
pub mod strrchr;
pub mod strstr;
pub mod valloc;
pub mod wcscmp;
pub mod wcscpy;
pub mod wcslen;
pub mod write;

#[cfg(feature = "libc")]
pub mod fgets;

use alloc::vec::Vec;
use core::ffi::{CStr, c_char, c_int, c_void};

use crate::{GuestAddr, hooks, size_t, wchar_t};

unsafe extern "C" {
    pub fn asprintf(strp: *mut *mut c_char, fmt: *const c_char, ...) -> c_int;
    pub fn vasprintf(strp: *mut *mut c_char, fmt: *const c_char, va: *const c_void) -> c_int;
}

#[derive(Clone)]
pub struct PatchedHook {
    pub name: &'static CStr,
    pub destination: GuestAddr,
}

impl PatchedHook {
    pub const fn new<F: Copy>(name: &'static CStr, func: F) -> Self {
        let pf = (&func) as *const F as *const GuestAddr;
        let destination = unsafe { *pf };
        Self { name, destination }
    }

    pub fn all() -> Vec<Self> {
        [
            PatchedHook::new::<unsafe extern "C" fn(size_t, size_t) -> *mut c_void>(
                c"aligned_alloc",
                hooks::aligned_alloc::aligned_alloc,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*mut *mut c_char, *const c_char, ...) -> c_int>(
                c"asprintf",
                hooks::asprintf,
            ),
            PatchedHook::new::<
                unsafe extern "C" fn(*const c_void, *const c_void, n: size_t) -> c_int,
            >(c"bcmp", hooks::bcmp::bcmp),
            PatchedHook::new::<unsafe extern "C" fn(*mut c_void, size_t)>(
                c"bzero",
                hooks::bzero::bzero,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*mut c_void, size_t)>(
                c"explicit_bzero",
                hooks::explicit_bzero::explicit_bzero,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_void, c_int, size_t) -> *mut c_void>(
                c"memchr",
                hooks::memchr::memchr,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_void, *const c_void, size_t) -> c_int>(
                c"memcmp",
                hooks::memcmp::memcmp,
            ),
            PatchedHook::new::<
                unsafe extern "C" fn(*mut c_void, *const c_void, size_t) -> *mut c_void,
            >(c"memcpy", hooks::memcpy::memcpy),
            PatchedHook::new::<
                unsafe extern "C" fn(*const c_void, size_t, *const c_void, size_t) -> *mut c_void,
            >(c"memmem", hooks::memmem::memmem),
            PatchedHook::new::<
                unsafe extern "C" fn(*mut c_void, *const c_void, size_t) -> *mut c_void,
            >(c"memmove", hooks::memmove::memmove),
            PatchedHook::new::<
                unsafe extern "C" fn(*mut c_void, *const c_void, size_t) -> *mut c_void,
            >(c"mempcpy", hooks::mempcpy::mempcpy),
            PatchedHook::new::<unsafe extern "C" fn(*const c_void, c_int, size_t) -> *mut c_void>(
                c"memrchr",
                hooks::memrchr::memrchr,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*mut c_char, *const c_char) -> *mut c_char>(
                c"stpcpy",
                hooks::stpcpy::stpcpy,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, *const c_char) -> c_int>(
                c"strcasecmp",
                hooks::strcasecmp::strcasecmp,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char>(
                c"strcasestr",
                hooks::strcasestr::strcasestr,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*mut c_char, *const c_char) -> *mut c_char>(
                c"strcat",
                hooks::strcat::strcat,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, c_int) -> *mut c_char>(
                c"strchr",
                hooks::strchr::strchr,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, *const c_char) -> c_int>(
                c"strcmp",
                hooks::strcmp::strcmp,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*mut c_char, *const c_char) -> *mut c_char>(
                c"strcpy",
                hooks::strcpy::strcpy,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char) -> *mut c_char>(
                c"strdup",
                hooks::strdup::strdup,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char) -> size_t>(
                c"strlen",
                hooks::strlen::strlen,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, *const c_char, size_t) -> c_int>(
                c"strncasecmp",
                hooks::strncasecmp::strncasecmp,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, *const c_char, size_t) -> c_int>(
                c"strncmp",
                hooks::strncmp::strncmp,
            ),
            PatchedHook::new::<
                unsafe extern "C" fn(*mut c_char, *const c_char, size_t) -> *mut c_char,
            >(c"strncpy", hooks::strncpy::strncpy),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, size_t) -> *mut c_char>(
                c"strndup",
                hooks::strndup::strndup,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, size_t) -> size_t>(
                c"strnlen",
                hooks::strnlen::strnlen,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, c_int) -> *mut c_char>(
                c"strrchr",
                hooks::strrchr::strrchr,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char>(
                c"strstr",
                hooks::strstr::strstr,
            ),
            PatchedHook::new::<
                unsafe extern "C" fn(*mut *mut c_char, *const c_char, *const c_void) -> c_int,
            >(c"vasprintf", hooks::vasprintf),
            PatchedHook::new::<unsafe extern "C" fn(*const wchar_t, *const wchar_t) -> c_int>(
                c"wcscmp",
                hooks::wcscmp::wcscmp,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*mut wchar_t, *const wchar_t) -> *mut wchar_t>(
                c"wcscpy",
                hooks::wcscpy::wcscpy,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*const wchar_t) -> size_t>(
                c"wcslen",
                hooks::wcslen::wcslen,
            ),
        ]
        .to_vec()
    }
}
