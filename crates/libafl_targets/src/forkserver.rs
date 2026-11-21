//! Forkserver logic into targets

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use libafl::executors::forkserver::FS_NEW_OPT_AUTODTCT;
#[cfg(feature = "cmplog")]
use libafl::executors::forkserver::SHM_CMPLOG_ENV_VAR;
use libafl::executors::forkserver::{
    AFL_MAP_SIZE_ENV_VAR, FORKSRV_FD, FS_ERROR_SHM_OPEN, FS_NEW_OPT_MAPSIZE,
    FS_NEW_OPT_SHDMEM_FUZZ, FS_NEW_VERSION_MAX, FS_OPT_ERROR, MAX_INPUT_SIZE_DEFAULT, SHM_ENV_VAR,
    SHM_FUZZ_ENV_VAR, SHM_FUZZ_MAP_SIZE_ENV_VAR, SHMEM_FUZZ_HDR_SIZE,
};
use libafl_bolts::{
    Error,
    os::{ChildHandle, ForkResult},
};
use nix::{
    sys::signal::{SigHandler, Signal},
    unistd::Pid,
};
use shmem_providers::{ShMem, ShMemId, ShMemProvider};

#[cfg(feature = "cmplog_extended_instrumentation")]
use crate::cmps::EXTENDED_CMPLOG_MAP_PTR;
#[cfg(feature = "cmplog")]
use crate::cmps::{AflppCmpLogMap, CMPLOG_MAP_PTR};
use crate::{
    EDGES_MAP_ALLOCATED_SIZE, EDGES_MAP_DEFAULT_SIZE,
    coverage::{__afl_map_size, EDGES_MAP_PTR, INPUT_LENGTH_PTR, INPUT_PTR, SHM_FUZZING},
};
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
use crate::{
    coverage::{__token_start, __token_stop},
    has_autotokens,
};

const FORKSRV_R_RAW_FD: libc::c_int = FORKSRV_FD;
const FORKSRV_W_RAW_FD: libc::c_int = FORKSRV_FD + 1;

fn fs_opt_set_error(error: i32) -> i32 {
    (error & 0xFFFF) << 8
}

unsafe fn write_raw_fd(fd: libc::c_int, buf: &[u8]) -> Result<usize, Error> {
    loop {
        let ret = unsafe { libc::write(fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
        if ret >= 0 {
            #[expect(clippy::cast_sign_loss)]
            return Ok(ret as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(Error::os_error(err, "write to forkserver fd failed"));
    }
}

unsafe fn read_raw_fd(fd: libc::c_int, buf: &mut [u8]) -> Result<usize, Error> {
    loop {
        let ret = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if ret >= 0 {
            #[expect(clippy::cast_sign_loss)]
            return Ok(ret as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(Error::os_error(err, "read from forkserver fd failed"));
    }
}

unsafe fn write_all_to_fd(fd: libc::c_int, mut message: &[u8]) -> Result<(), Error> {
    while !message.is_empty() {
        let bytes_written = unsafe { write_raw_fd(fd, message)? };
        if bytes_written == 0 {
            return Err(Error::illegal_state(
                "Could not write all bytes to target fd: write returned 0",
            ));
        }
        message = &message[bytes_written..];
    }
    Ok(())
}

unsafe fn write_u32_to_forkserver(message: u32) -> Result<(), Error> {
    unsafe { write_all_to_fd(FORKSRV_W_RAW_FD, &message.to_ne_bytes()) }
}

unsafe fn write_error_to_forkserver(error: i32) -> Result<(), Error> {
    if error <= 0 || error > 0xFFFF {
        return Err(Error::illegal_argument("illegal error sent to forkserver"));
    }
    #[expect(clippy::cast_sign_loss)]
    unsafe {
        write_u32_to_forkserver((fs_opt_set_error(error) | FS_OPT_ERROR) as u32)
    }
}

unsafe fn read_from_forkserver(mut message: &mut [u8]) -> Result<(), Error> {
    while !message.is_empty() {
        let bytes_read = unsafe { read_raw_fd(FORKSRV_R_RAW_FD, message)? };
        if bytes_read == 0 {
            return Err(Error::illegal_state("Unexpected EOF reading from forkserver"));
        }
        message = &mut message[bytes_read..];
    }
    Ok(())
}

unsafe fn read_u32_from_forkserver() -> Result<u32, Error> {
    let mut buf = [0u8; 4];
    unsafe { read_from_forkserver(&mut buf)? };
    Ok(u32::from_ne_bytes(buf))
}

fn leak_shmem<T: Sized>(shmem: impl ShMem) -> *mut T {
    core::mem::ManuallyDrop::new(shmem).as_mut_ptr().cast()
}

unsafe fn map_shared_memory_common<SHM: ShMemProvider>(
    shmem_provider: &mut SHM,
    map_env_var: &str,
    map_size_env_var: &str,
    map_size_default_fallback: usize,
) -> Result<SHM::ShMem, Error> {
    let Ok(id_str) = std::env::var(map_env_var) else {
        unsafe { write_error_to_forkserver(FS_ERROR_SHM_OPEN)? };
        return Err(Error::illegal_argument(format!(
            "Error: shared memory variable {map_env_var} is not set"
        )));
    };
    let map_size = if let Ok(map_size_str) = std::env::var(map_size_env_var) {
        map_size_str.parse().map_err(|err| {
            Error::illegal_argument(format!("Invalid {map_size_env_var} value: {err:?}"))
        })?
    } else {
        map_size_default_fallback
    };
    if map_size == 0 {
        return Err(Error::illegal_argument(format!(
            "Shared memory size for {map_env_var} must be greater than 0"
        )));
    }

    shmem_provider.shmem_from_id_and_size(ShMemId::from_string(&id_str), map_size)
}

/// Guard [`map_shared_memory`] is invoked only once
static SHM_MAP_GUARD: OnceLock<()> = OnceLock::new();

/// Map a shared memory region for the edge coverage map.
/// The [`EDGES_MAP_PTR`] will be updated.
///
/// If anything failed, the forkserver will be notified with
/// [`FS_ERROR_SHM_OPEN`].
///
/// # Safety
/// Forkserver fd `FORKSRV_FD + 1` must not alias an unrelated open file, and no thread may
/// concurrently access [`EDGES_MAP_PTR`].
pub unsafe fn map_shared_memory<SHM: ShMemProvider>(shmem_provider: &mut SHM) -> Result<(), Error> {
    if SHM_MAP_GUARD.set(()).is_err() {
        return Err(Error::illegal_state("shared memory has been mapped before"));
    }
    unsafe { map_shared_memory_internal(shmem_provider) }
}

unsafe fn map_shared_memory_internal<SHM: ShMemProvider>(
    shmem_provider: &mut SHM,
) -> Result<(), Error> {
    let raw_edges = unsafe {
        core::sync::atomic::AtomicUsize::from_ptr(&raw mut crate::coverage::MAX_EDGES_FOUND)
            .load(Ordering::Relaxed)
    };
    let clamped_edges = raw_edges.min(EDGES_MAP_ALLOCATED_SIZE);
    let required_edges = if cfg!(any(
        feature = "sancov_ngram4",
        feature = "sancov_ngram8",
        feature = "sancov_ctx"
    )) {
        clamped_edges.max(EDGES_MAP_DEFAULT_SIZE)
    } else {
        clamped_edges
    };
    let shmem = unsafe {
        map_shared_memory_common(
            shmem_provider,
            SHM_ENV_VAR,
            AFL_MAP_SIZE_ENV_VAR,
            required_edges.max(EDGES_MAP_DEFAULT_SIZE),
        )?
    };
    let mapped_len = shmem.len();
    if mapped_len < required_edges {
        return Err(Error::illegal_state(format!(
            "Mapped coverage region ({mapped_len} bytes) is smaller than required guard count ({required_edges})"
        )));
    }
    unsafe {
        core::sync::atomic::AtomicPtr::from_ptr(&raw mut EDGES_MAP_PTR)
            .store(leak_shmem(shmem), Ordering::Release);
    }
    Ok(())
}

/// Guard [`map_input_shared_memory`] is invoked only once
static INPUT_SHM_MAP_GUARD: OnceLock<()> = OnceLock::new();

/// Map the input shared memory region.
/// The [`INPUT_LENGTH_PTR`] and [`INPUT_PTR`] will be updated.
///
/// If anything failed, the forkserver will be notified with
/// [`FS_ERROR_SHM_OPEN`].
///
/// # Safety
/// Forkserver fd `FORKSRV_FD + 1` must not alias an unrelated open file, and no thread may
/// concurrently access [`INPUT_LENGTH_PTR`] or [`INPUT_PTR`].
pub unsafe fn map_input_shared_memory<SHM: ShMemProvider>(
    shmem_provider: &mut SHM,
) -> Result<(), Error> {
    if INPUT_SHM_MAP_GUARD.set(()).is_err() {
        return Err(Error::illegal_state("shared memory has been mapped before"));
    }
    unsafe { map_input_shared_memory_internal(shmem_provider) }
}

unsafe fn map_input_shared_memory_internal<SHM: ShMemProvider>(
    shmem_provider: &mut SHM,
) -> Result<(), Error> {
    let shmem = unsafe {
        map_shared_memory_common(
            shmem_provider,
            SHM_FUZZ_ENV_VAR,
            SHM_FUZZ_MAP_SIZE_ENV_VAR,
            MAX_INPUT_SIZE_DEFAULT + SHMEM_FUZZ_HDR_SIZE,
        )?
    };
    let mapped_len = shmem.len();
    if mapped_len < SHMEM_FUZZ_HDR_SIZE {
        return Err(Error::illegal_argument(format!(
            "Shared memory input region ({mapped_len} bytes) is smaller than header ({SHMEM_FUZZ_HDR_SIZE} bytes)"
        )));
    }
    if shmem.as_ptr_of::<u32>().is_none_or(|p| !p.is_aligned()) {
        return Err(Error::illegal_state(
            "Shared memory input region is not aligned for u32 length header",
        ));
    }
    let map: *mut u32 = leak_shmem(shmem);
    unsafe {
        core::sync::atomic::AtomicPtr::from_ptr(&raw mut INPUT_LENGTH_PTR)
            .store(map, Ordering::Release);
        core::sync::atomic::AtomicPtr::from_ptr(&raw mut INPUT_PTR)
            .store(map.add(1).cast(), Ordering::Release);
    }
    Ok(())
}

/// Guard [`map_cmplog_shared_memory`] is invoked only once
#[cfg(feature = "cmplog")]
static CMPLOG_SHM_MAP_GUARD: OnceLock<()> = OnceLock::new();

/// Map the cmplog shared memory region.
/// The [`CMPLOG_MAP_PTR`] will be updated.
///
/// If anything failed, the forkserver will be notified with
/// [`FS_ERROR_SHM_OPEN`].
///
/// # Safety
/// Forkserver fd `FORKSRV_FD + 1` must not alias an unrelated open file, and no thread may
/// concurrently access [`CMPLOG_MAP_PTR`].
#[cfg(feature = "cmplog")]
pub unsafe fn map_cmplog_shared_memory<SHM: ShMemProvider>(
    shmem_provider: &mut SHM,
) -> Result<(), Error> {
    if CMPLOG_SHM_MAP_GUARD.set(()).is_err() {
        return Err(Error::illegal_state("shared memory has been mapped before"));
    }
    unsafe { map_cmplog_shared_memory_internal(shmem_provider) }
}

#[cfg(feature = "cmplog")]
unsafe fn map_cmplog_shared_memory_internal<SHM: ShMemProvider>(
    shmem_provider: &mut SHM,
) -> Result<(), Error> {
    let Ok(id_str) = std::env::var(SHM_CMPLOG_ENV_VAR) else {
        unsafe { write_error_to_forkserver(FS_ERROR_SHM_OPEN)? };
        return Err(Error::illegal_argument(format!(
            "Error: shared memory variable {SHM_CMPLOG_ENV_VAR} is not set"
        )));
    };
    let map_size = size_of::<AflppCmpLogMap>();
    let shmem = shmem_provider.shmem_from_id_and_size(ShMemId::from_string(&id_str), map_size)?;
    if shmem.len() < map_size
        || shmem
            .as_ptr_of::<crate::cmps::CmpLogMap>()
            .is_none_or(|p| !p.is_aligned())
    {
        return Err(Error::illegal_state(
            "Shared memory cmplog region is too small or unaligned",
        ));
    }
    let target_ptr: *mut crate::cmps::CmpLogMap = leak_shmem(shmem);
    unsafe {
        core::sync::atomic::AtomicPtr::from_ptr(&raw mut CMPLOG_MAP_PTR)
            .store(target_ptr, Ordering::Release);
    }
    #[cfg(feature = "cmplog_extended_instrumentation")]
    unsafe {
        core::sync::atomic::AtomicPtr::from_ptr(&raw mut EXTENDED_CMPLOG_MAP_PTR)
            .store(target_ptr.cast::<AflppCmpLogMap>(), Ordering::Release);
    }
    Ok(())
}

/// Parent to handle all logics with forkserver children
pub trait ForkserverParent {
    /// Conduct initializing routine before fuzzing loop.
    ///
    /// Usually, several signal handlers are registered in this function.
    ///
    /// # Safety
    /// Implementations typically replace process-wide OS signal handlers (`SIGCHLD`, `SIGTERM`).
    unsafe fn pre_fuzzing(&mut self) -> Result<(), Error>;

    /// Spawn a child after the forkserver is ready.
    ///
    /// If the forkserver has killed previous child, `was_killed` will be
    /// set `true`.
    ///
    /// The actual forking should be conduct in this function, and in persistent mode,
    /// some tricks can be done to "fool" the forkserver that a child has been spawned.
    ///
    /// # Safety
    /// Implementations invoke `fork()`, so the calling process must be single-threaded when spawning a child.
    unsafe fn spawn_child(&mut self, was_killed: bool) -> Result<ForkResult, Error>;

    /// Interact with spawned child until the child has done its part.
    ///
    /// This function should return a status indicating the status of child. Usually,
    /// that status is determined by `waitpid`.
    fn handle_child_requests(&mut self) -> Result<i32, Error>;
}

/// Whether the forkserver loop is going to stop soon.
///
/// This will be set to true if user send SIGTERM.
static STOP_SOON: AtomicBool = AtomicBool::new(false);

/// Set [`STOP_SOON`] to be `true`. Then the forkserver parent will kill all children
/// and then exit asynchrously.
extern "C" fn std_handle_sigterm(_signal: libc::c_int) {
    STOP_SOON.store(true, Ordering::Relaxed);
}

/// Forkserver parent that can handle both non-persistent and persistent mode
#[derive(Debug, Default)]
pub struct MaybePersistentForkserverParent {
    last_child_pid: Option<i32>,
    /// This field is only touched for persistent mode to indicating
    /// whether the child is temporarily stopped or terminated
    child_stopped: bool,
    /// Whether the target is in persistent mode. When `true`, `waitpid`
    /// uses `WUNTRACED` so that the child's `SIGSTOP` (issued at the end
    /// of each persistent iteration) is detected and the child can be
    /// resumed with `SIGCONT` instead of being re-forked.
    is_persistent: bool,
    old_sigchld_handler: Option<SigHandler>,
    old_sigterm_handler: Option<SigHandler>,
}

impl MaybePersistentForkserverParent {
    /// Create a new forkserver parent.
    #[must_use]
    pub fn new() -> Self {
        MaybePersistentForkserverParent::default()
    }
}

impl ForkserverParent for MaybePersistentForkserverParent {
    unsafe fn pre_fuzzing(&mut self) -> Result<(), Error> {
        self.is_persistent = std::env::var("__AFL_PERSISTENT").is_ok_and(|v| v == "1");
        let old_sigchld_handler =
            (unsafe { nix::sys::signal::signal(Signal::SIGCHLD, SigHandler::SigDfl) })
                .inspect_err(|_| {
                    log::error!("Fail to swap signal handler for SIGCHLD.");
                })?;
        self.old_sigchld_handler = Some(old_sigchld_handler);
        let old_sigterm_handler = (unsafe {
            nix::sys::signal::signal(Signal::SIGTERM, SigHandler::Handler(std_handle_sigterm))
        })
        .inspect_err(|_| {
            log::error!("Fail to swap signal handler for SIGTERM.");
        })?;
        self.old_sigterm_handler = Some(old_sigterm_handler);

        Ok(())
    }

    unsafe fn spawn_child(&mut self, was_killed: bool) -> Result<ForkResult, Error> {
        if STOP_SOON.load(Ordering::Relaxed) {
            if let Some(child_pid) = self.last_child_pid.take() {
                nix::sys::signal::kill(Pid::from_raw(child_pid), Signal::SIGKILL)?;
            }
            std::process::exit(0);
        }
        // If we stopped the child in persistent mode, but there was a race
        // condition and afl-fuzz already issued SIGKILL, write off the old
        // process.
        if self.child_stopped && was_killed {
            self.child_stopped = false;
            // unwrap here: child_stopped is set as true only if it has spawned
            // a child, wait it, and get a stopped signal. Moreover, was_killed is
            // true only if the forkserver killed such child. In all cases, the
            // last_child_pid will never be None.
            if nix::sys::wait::waitpid(Pid::from_raw(self.last_child_pid.take().unwrap()), None)
                .is_err()
            {
                return Err(Error::illegal_state("child_stopped && was_killed"));
            }
        }

        if self.child_stopped {
            // Special handling for persistent mode: if the child is alive but
            // currently stopped, simply restart it with SIGCONT.

            // unwrap here: child_stopped is true only if last_child_pid is some.
            let child_pid = *self.last_child_pid.as_ref().unwrap();
            nix::sys::signal::kill(Pid::from_raw(child_pid), Signal::SIGCONT)?;
            self.child_stopped = false;
            Ok(ForkResult::Parent(ChildHandle { pid: child_pid }))
        } else {
            // Once woken up, create a clone of our process.
            let fork_result = (unsafe { libafl_bolts::os::fork() }).inspect_err(|_| {
                log::error!("fork");
            })?;
            match &fork_result {
                ForkResult::Parent(child_pid) => {
                    self.last_child_pid = Some(child_pid.pid);
                }
                ForkResult::Child => unsafe {
                    // unwrap here: the field is assigned in `pre_fuzzing`
                    nix::sys::signal::signal(
                        Signal::SIGCHLD,
                        self.old_sigchld_handler.take().unwrap(),
                    )
                    .inspect_err(|_| {
                        log::error!("Fail to restore signal handler for SIGCHLD.");
                    })?;
                    // unwrap here: the field is assigned in `pre_fuzzing`
                    nix::sys::signal::signal(
                        Signal::SIGTERM,
                        self.old_sigterm_handler.take().unwrap(),
                    )
                    .inspect_err(|_| {
                        log::error!("Fail to restore signal handler for SIGTERM.");
                    })?;
                },
            }
            Ok(fork_result)
        }
    }

    fn handle_child_requests(&mut self) -> Result<i32, Error> {
        let mut status = 0i32;
        // unwrap here: the field is assigned if we are parent process in `spawn_child`
        if unsafe {
            libc::waitpid(
                *self.last_child_pid.as_ref().unwrap(),
                &raw mut status,
                if self.is_persistent {
                    libc::WUNTRACED
                } else {
                    0
                },
            ) < 0
        } {
            return Err(Error::illegal_state("waitpid"));
        }
        if libc::WIFSTOPPED(status) {
            self.child_stopped = true;
        }
        Ok(status)
    }
}

/// Success state when [`start_forkserver`] returned.
#[derive(Debug)]
pub enum ForkserverState {
    /// There is no AFL forkserver responded. In such case,
    /// we should allow user to do a normal execution.
    NoAfl,
    /// Current process is a spawned child.
    Child,
}

/// Guard [`start_forkserver`] is invoked only once
static FORKSERVER_GUARD: OnceLock<()> = OnceLock::new();

/// Start a forkserver. This function will handle all communication
/// with AFL forkserver end, and use `forkserver_parent` to interact
/// with forked child.
///
/// This function will spawn a child in each round, and in the root process,
/// the loop will never return if everything is OK.
///
/// Before invoking this function, you should initialize [`EDGES_MAP_PTR`],
/// [`INPUT_PTR`] and [`INPUT_LENGTH_PTR`] properly. [`map_shared_memory`] and
/// [`map_input_shared_memory`] can be used, for example.
///
/// # Safety
///
/// The caller must ensure the process is single-threaded prior to forking, that file descriptors
/// `FORKSRV_FD` and `FORKSRV_FD + 1` are either closed or exclusively dedicated to the AFL
/// forkserver control/status pipes (never owned by Rust `OwnedFd`/`File` handles), and that
/// [`EDGES_MAP_PTR`], [`INPUT_PTR`], and [`INPUT_LENGTH_PTR`] have been validly initialized.
pub unsafe fn start_forkserver<P: ForkserverParent>(
    forkserver_parent: &mut P,
) -> Result<ForkserverState, Error> {
    if FORKSERVER_GUARD.set(()).is_err() {
        return Err(Error::illegal_state("forkserver has been started before"));
    }
    unsafe { start_forkserver_internal(forkserver_parent) }
}

const VERSION: u32 = 0x41464c00 + FS_NEW_VERSION_MAX;
unsafe fn start_forkserver_internal<P: ForkserverParent>(
    forkserver_parent: &mut P,
) -> Result<ForkserverState, Error> {
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    let autotokens_on = has_autotokens();
    let sharedmem_fuzzing = unsafe {
        core::sync::atomic::AtomicU32::from_ptr((&raw mut SHM_FUZZING).cast::<u32>())
            .load(Ordering::Acquire)
            == 1
    };

    // Parent supports testcases via shared map - and the user wants to use it. Tell AFL.
    // Phone home and tell the parent that we're OK. If parent isn't there, assume we're
    // not running in forkserver mode and just execute program.
    if unsafe { write_u32_to_forkserver(VERSION) }.is_err() {
        return Ok(ForkserverState::NoAfl);
    }

    let reply = unsafe { read_u32_from_forkserver()? };
    if reply != VERSION ^ 0xFFFFFFFF {
        return Err(Error::illegal_state(
            "wrong forkserver message from AFL++ tool",
        ));
    }

    let mut status = FS_NEW_OPT_MAPSIZE;
    if sharedmem_fuzzing {
        status |= FS_NEW_OPT_SHDMEM_FUZZ;
    }
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    if autotokens_on {
        status |= FS_NEW_OPT_AUTODTCT;
    }
    #[expect(clippy::cast_sign_loss)]
    unsafe {
        write_u32_to_forkserver(status as u32)?;
    }

    // Now send the parameters for the set options, increasing by option number

    // FS_NEW_OPT_MAPSIZE - we always send the map size
    let map_size = u32::try_from(unsafe {
        core::sync::atomic::AtomicUsize::from_ptr(&raw mut __afl_map_size).load(Ordering::Acquire)
    })
    .map_err(|_| Error::illegal_state("__afl_map_size exceeds u32::MAX"))?;
    unsafe { write_u32_to_forkserver(map_size)? };

    // FS_NEW_OPT_AUTODICT - send autotokens
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    if autotokens_on {
        let tokens_len_usize = unsafe { (__token_stop as usize) - (__token_start as usize) };
        let tokens_len = u32::try_from(tokens_len_usize)
            .map_err(|_| Error::illegal_state("autotokens section exceeds u32::MAX"))?;
        unsafe { write_u32_to_forkserver(tokens_len) }.inspect_err(|_| {
            log::error!("Error: could not send autotokens len");
        })?;
        unsafe {
            write_all_to_fd(
                FORKSRV_W_RAW_FD,
                core::slice::from_raw_parts(__token_start, tokens_len as usize),
            )
        }
        .inspect_err(|_| {
            log::error!("could not send autotokens");
        })?;
    }

    // send welcome message as final message
    unsafe { write_u32_to_forkserver(VERSION)? };

    unsafe { forkserver_parent.pre_fuzzing()? };

    loop {
        // Wait for parent by reading from the pipe. Abort if read fails.

        let was_killed = unsafe { read_u32_from_forkserver()? };

        let fork_result = unsafe { forkserver_parent.spawn_child(was_killed != 0)? };

        match fork_result {
            ForkResult::Child => {
                // FORKSRV_FD is for communication with AFL, we don't need it in the child
                unsafe {
                    if libc::close(FORKSRV_R_RAW_FD) < 0 {
                        log::debug!("Failed to close FORKSRV_R_RAW_FD in child");
                    }
                    if libc::close(FORKSRV_W_RAW_FD) < 0 {
                        log::debug!("Failed to close FORKSRV_W_RAW_FD in child");
                    }
                }
                return Ok(ForkserverState::Child);
            }
            ForkResult::Parent(child_pid) => {
                #[expect(clippy::cast_sign_loss)]
                unsafe { write_u32_to_forkserver(child_pid.pid as u32) }.inspect_err(|_| {
                    log::error!("write to afl-fuzz");
                })?;
            }
        }

        let status = forkserver_parent.handle_child_requests()?;

        // Relay wait status to AFL pipe, then loop back.
        #[expect(clippy::cast_sign_loss)]
        unsafe { write_u32_to_forkserver(status as u32) }.inspect_err(|_| {
            log::error!("writing to afl-fuzz");
        })?;
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_write_all_to_fd_advances_slice_completely() {
        let mut fds: [libc::c_int; 2] = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let payload: Vec<u8> = (0u8..=255).cycle().take(131_072).collect();
        let read_fd = fds[0];
        let write_fd = fds[1];
        let expected = payload.clone();

        let reader = std::thread::spawn(move || {
            let mut out = Vec::with_capacity(131_072);
            let mut chunk = [0u8; 4096];
            loop {
                let n = unsafe { read_raw_fd(read_fd, &mut chunk).unwrap() };
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&chunk[..n]);
            }
            assert_eq!(unsafe { libc::close(read_fd) }, 0);
            out
        });

        unsafe {
            write_all_to_fd(write_fd, &payload).unwrap();
            assert_eq!(libc::close(write_fd), 0);
        }

        assert_eq!(reader.join().unwrap(), expected);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_maybe_persistent_forkserver_parent_persistent_mode() {
        unsafe { std::env::set_var("__AFL_PERSISTENT", "1") };
        let mut parent = MaybePersistentForkserverParent::new();
        unsafe { parent.pre_fuzzing().unwrap() };
        unsafe { std::env::remove_var("__AFL_PERSISTENT") };

        let result = unsafe { parent.spawn_child(false).unwrap() };

        let first_pid = match result {
            ForkResult::Child => {
                unsafe { libc::raise(libc::SIGSTOP) };
                unsafe { libc::_exit(0) };
            }
            ForkResult::Parent(handle) => handle.pid,
        };

        let status = parent.handle_child_requests().unwrap();
        assert!(
            libc::WIFSTOPPED(status),
            "handle_child_requests should detect stopped child in persistent mode"
        );

        let result2 = unsafe { parent.spawn_child(false).unwrap() };
        match result2 {
            ForkResult::Parent(handle2) => {
                assert_eq!(
                    handle2.pid, first_pid,
                    "persistent mode should resume the same child, not fork a new one"
                );
            }
            ForkResult::Child => {
                panic!("persistent-mode spawn_child should not fork");
            }
        }

        let status2 = parent.handle_child_requests().unwrap();
        assert!(
            libc::WIFEXITED(status2),
            "child should exit after being resumed by SIGCONT"
        );
    }
}
