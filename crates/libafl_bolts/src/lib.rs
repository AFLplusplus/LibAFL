/*!
 * Welcome to `LibAFL_bolts`
 */
#![doc = include_str!("../README.md")]
/*! */
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]
#![no_std]
#![cfg_attr(not(test), warn(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
))]
#![cfg_attr(test, deny(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    //unused_results
))]
#![cfg_attr(
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]

#[cfg(feature = "std")]
#[macro_use]
extern crate std;
#[cfg(feature = "alloc")]
#[macro_use]
#[doc(hidden)]
pub extern crate alloc;

#[cfg(feature = "std")]
pub use build_id2 as build_id;
#[cfg(feature = "alloc")]
pub use serde_anymap::anymap;
#[cfg(all(
    any(feature = "cli", feature = "frida_cli", feature = "qemu_cli"),
    feature = "std"
))]
pub mod cli;
#[cfg(feature = "gzip")]
pub mod compress;
#[cfg(feature = "std")]
pub use core_affinity2 as core_affinity;
#[cfg(feature = "std")]
pub mod fs;
#[cfg(feature = "alloc")]
pub use ll_mp as llmp;
pub mod math;
#[cfg(feature = "std")]
pub use minibsod;
pub mod os;
#[cfg(feature = "alloc")]
pub use serde_anymap::serdeany;
#[cfg(feature = "std")]
pub mod staterestore;
#[cfg(any(feature = "xxh3", feature = "alloc"))]
pub use tuple_list_ex as tuples;

#[cfg(all(feature = "std", unix))]
pub mod argparse;
#[cfg(all(feature = "std", unix))]
pub use argparse::*;

#[cfg(feature = "std")]
pub mod target_args;
pub use fast_rands as rands;
#[allow(deprecated)]
pub use libafl_core::{
    AsIter, AsIterMut, AsSizedSlice, AsSizedSliceMut, AsSlice, AsSliceMut, ClientId, Error, HasLen,
    HasRefCnt, Named, ToSizedSlice, ToSizedSliceMut, ToSlice, ToSliceMut, Truncate,
};
#[cfg(feature = "alloc")]
pub use no_std_time::format_duration;
pub use no_std_time::{current_milliseconds, current_nanos, current_time};
pub use ownedref::{self, subrange};
#[cfg(feature = "alloc")]
pub use serde_anymap::impl_serdeany;
pub use shmem_providers as shmem;
#[cfg(feature = "std")]
pub use target_args::*;

pub mod simd;

/// The purpose of this module is to alleviate imports of the bolts by adding a glob import.
#[cfg(feature = "prelude")]
pub mod bolts_prelude {
    #[cfg(feature = "std")]
    pub use super::build_id::*;
    #[cfg(all(
        any(feature = "cli", feature = "frida_cli", feature = "qemu_cli"),
        feature = "std"
    ))]
    pub use super::cli::*;
    #[cfg(feature = "gzip")]
    pub use super::compress::*;
    #[cfg(feature = "std")]
    pub use super::core_affinity::*;
    #[cfg(feature = "std")]
    pub use super::fs::*;
    #[cfg(all(feature = "std", unix))]
    pub use super::minibsod::*;
    pub use super::os::*;
    #[cfg(feature = "std")]
    pub use super::staterestore::*;
    #[cfg(feature = "alloc")]
    pub use super::{anymap::*, llmp::*, ownedref::*, rands::*, serdeany::*, shmem::*, tuples::*};
}

#[cfg(all(unix, feature = "std"))]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::string::ToString;
#[cfg(all(not(feature = "xxh3"), feature = "alloc"))]
use core::hash::BuildHasher;
#[cfg(any(feature = "xxh3", feature = "alloc"))]
use core::hash::{Hash, Hasher};
#[cfg(all(unix, feature = "std"))]
use std::{
    fs::File,
    io::Write,
    os::fd::{FromRawFd, RawFd},
    panic,
};

// There's a bug in ahash that doesn't let it build in `alloc` without once_cell right now.
// TODO: re-enable once <https://github.com/tkaitchuck/aHash/issues/155> is resolved.
#[cfg(all(not(feature = "xxh3"), feature = "alloc"))]
use ahash::RandomState;
#[cfg(feature = "libafl_derive")]
pub use libafl_derive::SerdeAny;
#[cfg(feature = "std")]
use log::{Metadata, Record};
#[cfg(feature = "xxh3")]
use xxhash_rust::xxh3::xxh3_64;

/// Returns the standard input [`Hasher`]
///
/// Returns the hasher for the input with a given hash, depending on features:
/// [`xxh3_64`](https://docs.rs/xxhash-rust/latest/xxhash_rust/xxh3/fn.xxh3_64.html)
/// if the `xxh3` feature is used, /// else [`ahash`](https://docs.rs/ahash/latest/ahash/).
#[cfg(any(feature = "xxh3", feature = "alloc"))]
#[must_use]
pub fn hasher_std() -> impl Hasher + Clone {
    #[cfg(feature = "xxh3")]
    return xxhash_rust::xxh3::Xxh3::new();
    #[cfg(not(feature = "xxh3"))]
    RandomState::with_seeds(0, 0, 0, 0).build_hasher()
}

/// Hashes the input with a given hash
///
/// Hashes the input with a given hash, depending on features:
/// [`xxh3_64`](https://docs.rs/xxhash-rust/latest/xxhash_rust/xxh3/fn.xxh3_64.html)
/// if the `xxh3` feature is used, /// else [`ahash`](https://docs.rs/ahash/latest/ahash/).
#[cfg(any(feature = "xxh3", feature = "alloc"))]
#[must_use]
pub fn hash_std(input: &[u8]) -> u64 {
    #[cfg(feature = "xxh3")]
    return xxh3_64(input);
    #[cfg(not(feature = "xxh3"))]
    {
        let mut hasher = hasher_std();
        hasher.write(input);
        hasher.finish()
    }
}

/// Fast hash function for 64 bits integers minimizing collisions.
/// Adapted from <https://xorshift.di.unimi.it/splitmix64.c>
#[must_use]
pub fn hash_64_fast(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

/// Hashes the input with a given hash
///
/// Hashes the input with a given hash, depending on features:
/// [`xxh3_64`](https://docs.rs/xxhash-rust/latest/xxhash_rust/xxh3/fn.xxh3_64.html)
/// if the `xxh3` feature is used, /// else [`ahash`](https://docs.rs/ahash/latest/ahash/).
///
/// If you have access to a `&[u8]` directly, [`hash_std`] may provide better performance
#[cfg(any(feature = "xxh3", feature = "alloc"))]
#[must_use]
pub fn generic_hash_std<I: Hash>(input: &I) -> u64 {
    let mut hasher = hasher_std();
    input.hash(&mut hasher);
    hasher.finish()
}

/// The purpose of this module is to alleviate imports of many components by adding a glob import.
#[cfg(feature = "prelude")]
pub mod prelude {
    #![allow(ambiguous_glob_reexports)]

    pub use super::{bolts_prelude::*, *};
}

/// Format a number with thousands separators
#[cfg(feature = "alloc")]
#[must_use]
pub fn format_big_number(val: u64) -> String {
    let short = {
        let (num, unit) = match val {
            0..=999 => return format!("{val}"),
            1_000..=999_999 => (1000, "K"),
            1_000_000..=999_999_999 => (1_000_000, "M"),
            1_000_000_000..=999_999_999_999 => (1_000_000_000, "G"),
            _ => (1_000_000_000_000, "T"),
        };
        let main = val / num;
        let frac = (val % num) / (num / 100);
        format!(
            "{}.{}{}",
            main,
            format!("{frac:02}").trim_end_matches('0'),
            unit
        )
    };
    let long = val
        .to_string()
        .chars()
        .rev()
        .enumerate()
        .fold(String::new(), |mut acc, (i, c)| {
            if i > 0 && i.is_multiple_of(3) {
                acc.push(',');
            }
            acc.push(c);
            acc
        })
        .chars()
        .rev()
        .collect::<String>();
    format!("{short} ({long})")
}

/// Stderr logger
#[cfg(feature = "std")]
pub static LIBAFL_STDERR_LOGGER: SimpleStderrLogger = SimpleStderrLogger::new();

/// Stdout logger
#[cfg(feature = "std")]
pub static LIBAFL_STDOUT_LOGGER: SimpleStdoutLogger = SimpleStdoutLogger::new();

/// A logger we can use log to raw fds.
#[cfg(all(unix, feature = "std"))]
static LIBAFL_RAWFD_LOGGER: SimpleFdLogger = unsafe { SimpleFdLogger::new(1) };

/// A simple logger struct that logs to stdout when used with [`log::set_logger`].
#[derive(Debug)]
#[cfg(feature = "std")]
pub struct SimpleStdoutLogger {}

#[cfg(feature = "std")]
impl Default for SimpleStdoutLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl SimpleStdoutLogger {
    /// Create a new [`log::Log`] logger that will write log to stdout
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// register stdout logger
    pub fn set_logger() -> Result<(), Error> {
        log::set_logger(&LIBAFL_STDOUT_LOGGER)
            .map_err(|err| Error::illegal_state(format!("Failed to set logger: {err:?}")))
    }
}

#[cfg(feature = "std")]
#[cfg(target_os = "windows")]
#[allow(clippy::cast_ptr_alignment)]
#[must_use]
/// Return thread ID without using TLS
pub fn get_thread_id() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let teb: *const u8;
        core::arch::asm!("mov {}, gs:[0x30]", out(reg) teb);
        let thread_id_ptr = teb.add(0x48) as *const u32;
        u64::from(*thread_id_ptr)
    }

    #[cfg(target_arch = "x86")]
    unsafe {
        let teb: *const u8;
        core::arch::asm!("mov {}, fs:[0x18]", out(reg) teb);
        let thread_id_ptr = teb.add(0x24) as *const u32;
        *thread_id_ptr as u64
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    unsafe {
        u64::from(winapi::um::processthreadsapi::GetCurrentThreadId())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[must_use]
#[allow(clippy::cast_sign_loss)]
/// Return thread ID without using TLS
pub fn get_thread_id() -> u64 {
    use libc::{SYS_gettid, syscall};

    unsafe { syscall(SYS_gettid) as u64 }
}

#[cfg(target_vendor = "apple")]
#[must_use]
/// Return thread ID without using TLS
pub fn get_thread_id() -> u64 {
    let mut tid = 0u64;
    // SAFETY: Passing thread = 0 queries the calling thread's kernel ID into `tid` without TLS.
    unsafe {
        libc::pthread_threadid_np(0, &raw mut tid);
    }
    tid
}

#[cfg(feature = "std")]
#[cfg(not(any(
    target_os = "windows",
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple"
)))]
#[must_use]
/// Return thread ID using a thread-local monotonic counter.
pub fn get_thread_id() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};

    static NEXT_THREAD_ID: AtomicU64 = AtomicU64::new(1);
    std::thread_local! {
        static THREAD_ID: u64 = NEXT_THREAD_ID.fetch_add(1, Ordering::Relaxed);
    }
    THREAD_ID.try_with(|id| *id).unwrap_or(0)
}

#[cfg(feature = "std")]
#[cfg(target_os = "windows")]
mod windows_logging {
    use core::ptr;
    use std::sync::OnceLock;

    use winapi::um::{
        fileapi::WriteFile, handleapi::INVALID_HANDLE_VALUE, processenv::GetStdHandle,
        winbase::STD_OUTPUT_HANDLE, winnt::HANDLE,
    };

    // Safe wrapper around HANDLE
    struct StdOutHandle(HANDLE);

    // Implement Send and Sync for StdOutHandle, assuming it's safe to share
    unsafe impl Send for StdOutHandle {}
    unsafe impl Sync for StdOutHandle {}

    static H_STDOUT: OnceLock<StdOutHandle> = OnceLock::new();

    fn get_stdout_handle() -> HANDLE {
        H_STDOUT
            .get_or_init(|| {
                let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
                StdOutHandle(handle)
            })
            .0
    }
    /// A function that writes directly to stdout using `WinAPI`.
    /// Works much faster than println and does not need TLS
    pub fn direct_log(message: &str) {
        // Get the handle to standard output
        let h_stdout: HANDLE = get_stdout_handle();

        if ptr::addr_eq(h_stdout, INVALID_HANDLE_VALUE) {
            eprintln!("Failed to get standard output handle");
            return;
        }

        let bytes = message.as_bytes();
        let mut bytes_written = 0;

        // Write the message to standard output
        let result = unsafe {
            WriteFile(
                h_stdout,
                bytes.as_ptr() as *const _,
                bytes.len() as u32,
                &raw mut bytes_written,
                ptr::null_mut(),
            )
        };

        if result == 0 {
            eprintln!("Failed to write to standard output");
        }
    }
}

#[cfg(feature = "std")]
impl log::Log for SimpleStdoutLogger {
    #[inline]
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    #[cfg(not(target_os = "windows"))]
    fn log(&self, record: &Record) {
        println!(
            "[{:?}, {:?}:{:?}] {}: {}",
            current_time(),
            std::process::id(),
            get_thread_id(),
            record.level(),
            record.args()
        );
    }

    #[cfg(target_os = "windows")]
    fn log(&self, record: &Record) {
        // println is not safe in TLS-less environment
        let msg = format!(
            "[{:?}, {:?}:{:?}] {}: {}\n",
            current_time(),
            std::process::id(),
            get_thread_id(),
            record.level(),
            record.args()
        );
        windows_logging::direct_log(msg.as_str());
    }

    fn flush(&self) {}
}

/// A simple logger struct that logs to stderr when used with [`log::set_logger`].
#[derive(Debug)]
#[cfg(feature = "std")]
pub struct SimpleStderrLogger {}

#[cfg(feature = "std")]
impl Default for SimpleStderrLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl SimpleStderrLogger {
    /// Create a new [`log::Log`] logger that will write log to stdout
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }

    /// register stderr logger
    pub fn set_logger() -> Result<(), Error> {
        log::set_logger(&LIBAFL_STDERR_LOGGER)
            .map_err(|err| Error::illegal_state(format!("Could not set logger: {err:?}")))
    }
}

#[cfg(feature = "std")]
impl log::Log for SimpleStderrLogger {
    #[inline]
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        eprintln!(
            "[{:?}, {:?}] {}: {}",
            current_time(),
            std::process::id(),
            record.level(),
            record.args()
        );
    }

    fn flush(&self) {}
}

/// A simple logger struct that logs to a `RawFd` when used with [`log::set_logger`].
#[derive(Debug)]
#[cfg(all(feature = "std", unix))]
pub struct SimpleFdLogger {
    fd: core::sync::atomic::AtomicI32,
}

#[cfg(all(feature = "std", unix))]
impl SimpleFdLogger {
    /// Create a new [`log::Log`] logger that will write the log to the given `fd`
    ///
    /// # Safety
    /// `fd` must remain a valid open file descriptor writable for as long as this logger is used.
    #[must_use]
    pub const unsafe fn new(fd: RawFd) -> Self {
        Self {
            fd: core::sync::atomic::AtomicI32::new(fd),
        }
    }

    /// Sets the `fd` this logger will write to
    ///
    /// # Safety
    /// `fd` must remain a valid open file descriptor writable for as long as this logger is used.
    pub unsafe fn set_fd(&self, fd: RawFd) {
        self.fd.store(fd, core::sync::atomic::Ordering::Relaxed);
    }

    /// Register this logger, logging to the given `fd`
    ///
    /// # Safety
    /// `log_fd` must remain a valid open file descriptor writable for the remainder of the process.
    pub unsafe fn set_logger(log_fd: RawFd) -> Result<(), Error> {
        if log_fd < 0 {
            return Err(Error::illegal_argument("log_fd must be non-negative"));
        }
        let prev = LIBAFL_RAWFD_LOGGER
            .fd
            .swap(log_fd, core::sync::atomic::Ordering::Relaxed);
        log::set_logger(&LIBAFL_RAWFD_LOGGER).map_err(|err| {
            LIBAFL_RAWFD_LOGGER
                .fd
                .store(prev, core::sync::atomic::Ordering::Relaxed);
            Error::illegal_state(format!("Could not set logger: {err:?}"))
        })
    }
}

#[cfg(all(feature = "std", unix))]
impl log::Log for SimpleFdLogger {
    #[inline]
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let fd = self.fd.load(core::sync::atomic::Ordering::Relaxed);
        if fd < 0 {
            return;
        }
        let mut f = core::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
        writeln!(
            f,
            "[{:?}, {:#?}] {}: {}",
            current_time(),
            std::process::id(),
            record.level(),
            record.args()
        )
        .unwrap_or_else(|err| println!("Failed to log to fd {fd}: {err}"));
    }

    fn flush(&self) {}
}

/// Set up an error print hook that will write panic diagnostics to `new_stderr`.
///
/// # Safety
/// `new_stderr` must remain a valid open file descriptor writable whenever the panic hook may fire.
#[cfg(all(unix, feature = "std"))]
pub unsafe fn set_error_print_panic_hook(new_stderr: RawFd) {
    if new_stderr < 0 {
        return;
    }
    panic::set_hook(Box::new(move |panic_info| {
        let mut f = core::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(new_stderr) });
        writeln!(f, "{panic_info}")
            .unwrap_or_else(|err| println!("Failed to log to fd {new_stderr}: {err}"));
    }));
}

#[cfg(all(feature = "std", target_os = "windows", target_arch = "x86_64"))]
#[repr(C)]
#[allow(clippy::upper_case_acronyms)]
struct TEB {
    reserved1: [u8; 0x58],
    tls_pointer: *mut *mut u8,
    reserved2: [u8; 0xC0],
}

#[cfg(feature = "std")]
#[cfg(target_arch = "x86_64")]
#[inline(always)]
#[cfg(target_os = "windows")]
fn nt_current_teb() -> *mut TEB {
    use core::arch::asm;
    let teb: *mut TEB;
    unsafe {
        asm!("mov {}, gs:0x30", out(reg) teb);
    }
    teb
}

/// Some of our hooks can be invoked from threads that do not have TLS yet.
/// Many Rust and Frida functions require TLS to be set up, so we need to check if we have TLS.
/// This was observed on Windows, so for now for other platforms we assume that we have TLS.
#[cfg(feature = "std")]
#[inline]
#[allow(unreachable_code)]
#[must_use]
pub fn has_tls() -> bool {
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe {
        let teb = nt_current_teb();
        if teb.is_null() {
            return false;
        }

        let tls_array = (*teb).tls_pointer;
        if tls_array.is_null() {
            return false;
        }
        return true;
    }
    #[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
    unsafe {
        let mut tid: u64;
        core::arch::asm!(
            "mrs {tid}, TPIDRRO_EL0",
            tid = out(reg) tid,
        );
        tid &= 0xffff_ffff_ffff_fff8;
        let tlsptr = tid as *const u64;
        if tlsptr.is_null() {
            return false;
        }
        return tlsptr.add(0x102).read() != 0u64;
    }
    // Default
    true
}

pub use nonzero_macros;
#[doc(inline)]
pub use nonzero_macros::{nonnull_raw_mut, nonzero, try_nonzero};

#[cfg(feature = "python")]
#[allow(missing_docs)] // expect somehow breaks here
pub mod pybind {

    use pyo3::{Bound, PyResult, pymodule, types::PyModule};

    #[macro_export]
    macro_rules! unwrap_me_body {
        ($wrapper:expr, $name:ident, $body:block, $wrapper_type:ident, { $($wrapper_option:tt),* }) => {
            match &$wrapper {
                $(
                    $wrapper_type::$wrapper_option(py_wrapper) => {
                        Python::attach(|py| -> PyResult<_> {
                            let borrowed = py_wrapper.borrow(py);
                            let $name = &borrowed.inner;
                            Ok($body)
                        })
                        .unwrap()
                    }
                )*
            }
        };
        ($wrapper:expr, $name:ident, $body:block, $wrapper_type:ident, { $($wrapper_option:tt),* }, { $($wrapper_optional:tt($pw:ident) => $code_block:block)* }) => {
            match &$wrapper {
                $(
                    $wrapper_type::$wrapper_option(py_wrapper) => {
                        Python::attach(|py| -> PyResult<_> {
                            let borrowed = py_wrapper.borrow(py);
                            let $name = &borrowed.inner;
                            Ok($body)
                        })
                        .unwrap()
                    }
                )*
                $($wrapper_type::$wrapper_optional($pw) => { $code_block })*
            }
        };
    }

    #[macro_export]
    macro_rules! impl_serde_pyobjectwrapper {
        ($struct_name:ident, $inner:tt) => {
            const _: () = {
                use alloc::vec::Vec;

                use pyo3::prelude::*;
                use serde::{Deserialize, Deserializer, Serialize, Serializer};

                impl Serialize for $struct_name {
                    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where
                        S: Serializer,
                    {
                        let buf = Python::attach(|py| -> PyResult<Vec<u8>> {
                            let pickle = PyModule::import(py, "pickle")?;
                            let buf: Vec<u8> =
                                pickle.getattr("dumps")?.call1((&self.$inner,))?.extract()?;
                            Ok(buf)
                        })
                        .unwrap();
                        serializer.serialize_bytes(&buf)
                    }
                }

                struct PyObjectVisitor;

                impl<'de> serde::de::Visitor<'de> for PyObjectVisitor {
                    type Value = $struct_name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter
                            .write_str("Expecting some bytes to deserialize from the Python side")
                    }

                    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        let obj = Python::attach(|py| -> PyResult<PyObject> {
                            let pickle = PyModule::import(py, "pickle")?;
                            let obj = pickle.getattr("loads")?.call1((v,))?.unbind();
                            Ok(obj)
                        })
                        .unwrap();
                        Ok($struct_name::new(obj))
                    }
                }

                impl<'de> Deserialize<'de> for $struct_name {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: Deserializer<'de>,
                    {
                        deserializer.deserialize_byte_buf(PyObjectVisitor)
                    }
                }
            };
        };
    }

    #[pymodule]
    #[pyo3(name = "libafl_bolts")]
    /// Register the classes to the python module
    pub fn python_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
        crate::rands::pybind::register(m)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    #[cfg(all(feature = "std", unix))]
    use crate::LIBAFL_RAWFD_LOGGER;

    #[test]
    #[cfg(all(unix, feature = "std"))]
    fn test_logger() {
        use core::sync::atomic::Ordering;
        use std::{
            io::{stderr, stdout},
            os::fd::AsRawFd,
        };

        use crate::SimpleFdLogger;

        let out_fd = stdout().as_raw_fd();
        assert!(unsafe { SimpleFdLogger::set_logger(-1) }.is_err());
        unsafe { SimpleFdLogger::set_logger(out_fd) }.unwrap();
        assert!(unsafe { SimpleFdLogger::set_logger(stderr().as_raw_fd()) }.is_err());
        assert_eq!(LIBAFL_RAWFD_LOGGER.fd.load(Ordering::Relaxed), out_fd);
        log::set_max_level(log::LevelFilter::Debug);
        log::info!("Test");
    }

    #[test]
    #[cfg(feature = "std")]
    #[cfg_attr(miri, ignore)]
    fn test_get_thread_id() {
        use crate::{get_thread_id, has_tls};

        let tls = has_tls();
        #[cfg(not(all(target_arch = "aarch64", target_vendor = "apple")))]
        assert!(tls);
        #[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
        core::hint::black_box(tls);
        let main_id = get_thread_id();
        assert_ne!(main_id, 0);
        assert_eq!(main_id, get_thread_id());

        let child_id = std::thread::spawn(get_thread_id).join().unwrap();
        assert_ne!(child_id, 0);
        assert_ne!(child_id, main_id);
    }
}
