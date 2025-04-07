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
pub mod rawmemchr;
pub mod read;
pub mod realloc;
pub mod reallocarray;
pub mod stpcpy;
pub mod stpncpy;
pub mod strcasecmp;
pub mod strcasestr;
pub mod strcat;
pub mod strchr;
pub mod strchrnul;
pub mod strcmp;
pub mod strcpy;
pub mod strdup;
pub mod strlen;
pub mod strncasecmp;
pub mod strncat;
pub mod strncmp;
pub mod strncpy;
pub mod strndup;
pub mod strnlen;
pub mod strrchr;
pub mod strstr;
pub mod valloc;
pub mod wcschr;
pub mod wcscmp;
pub mod wcscpy;
pub mod wcslen;
pub mod wcsncmp;
pub mod wcsnlen;
pub mod wcsrchr;
pub mod wmemchr;
pub mod write;

#[cfg(feature = "libc")]
pub mod fgets;

use alloc::vec::{IntoIter, Vec};
use core::ffi::{CStr, c_char, c_int, c_void};

use crate::{GuestAddr, hooks, size_t, symbols::Symbols, wchar_t};

unsafe extern "C" {
    pub fn asprintf(strp: *mut *mut c_char, fmt: *const c_char, ...) -> c_int;
    pub fn vasprintf(strp: *mut *mut c_char, fmt: *const c_char, va: *const c_void) -> c_int;
}

#[derive(Debug, Clone)]
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

    pub fn lookup<S: Symbols>(&self) -> Result<GuestAddr, S::Error> {
        S::lookup(self.name.as_ptr() as *const c_char)
    }
}

pub struct PatchedHooks {
    hooks: Vec<PatchedHook>,
}

impl IntoIterator for PatchedHooks {
    type Item = PatchedHook;
    type IntoIter = IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.hooks.into_iter()
    }
}

impl Default for PatchedHooks {
    fn default() -> Self {
        Self { hooks: [
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
            PatchedHook::new::<unsafe extern "C" fn(*const c_void, c_int) -> *mut c_void>(
                c"rawmemchr",
                hooks::rawmemchr::rawmemchr,
            ),
            PatchedHook::new::<unsafe extern "C" fn(*mut c_char, *const c_char) -> *mut c_char>(
                c"stpcpy",
                hooks::stpcpy::stpcpy,
            ),
            PatchedHook::new::<
                unsafe extern "C" fn(*mut c_char, *const c_char, size_t) -> *mut c_char,
            >(c"stpncpy", hooks::stpncpy::stpncpy),
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
            PatchedHook::new::<unsafe extern "C" fn(*const c_char, c_int) -> *mut c_char>(
                c"strchrnul",
                hooks::strchrnul::strchrnul,
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
            PatchedHook::new::<
                unsafe extern "C" fn(*mut c_char, *const c_char, size_t) -> *mut c_char,
            >(c"strncat", hooks::strncat::strncat),
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
            PatchedHook::new::<unsafe extern "C" fn(*const wchar_t, c_int) -> *mut wchar_t>(
                c"wcschr",
                hooks::wcschr::wcschr,
            ),
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
            PatchedHook::new::<unsafe extern "C" fn (*const wchar_t, *const wchar_t, size_t) -> c_int>(
                c"wcsncmp",
                hooks::wcsncmp::wcsncmp,
            ),
            PatchedHook::new::<unsafe extern "C" fn ( *const wchar_t,  size_t) -> size_t>(
                c"wcsnlen",
                hooks::wcsnlen::wcsnlen,
            ),
            PatchedHook::new::<unsafe extern "C" fn ( *const wchar_t,  c_int) -> *mut wchar_t >(
                c"wcsrchr",
                hooks::wcsrchr::wcsrchr,
            ),
            PatchedHook::new::<unsafe extern "C" fn ( *const wchar_t,  wchar_t,  size_t) -> *mut wchar_t>(
                c"wmemchr",
                hooks::wmemchr::wmemchr,
            ),

        ]
        .to_vec() }
    }
}
