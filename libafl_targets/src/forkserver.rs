//! Forkserver logic into targets

/// Trait to implement hooks executed in the forkserver
pub trait ForkserverHooks {
    /// Execute before the fork that creates the child
    extern "C" fn pre_fork(&mut self);
    /// Executed after the fork (pid == 0 means child process)
    extern "C" fn post_fork(&mut self, pid: libc::pid_t);
    /// Execute in the parent after the iteration start in the child
    extern "C" fn iter_start(&mut self);
    /// Execute in the parent after the iteration end (by waitpid) in the child
    extern "C" fn iter_end(&mut self, status: i32);
}

#[repr(C)]
struct CForkserverHooks<H: ForkserverHooks> {
    data: *mut H,
    pre_fork_hook: extern "C" fn(*mut H),
    post_fork_hook: extern "C" fn(*mut H, libc::pid_t),
    iteration_start_hook: extern "C" fn(*mut H),
    iteration_end_hook: extern "C" fn(*mut H, i32),
}

extern "C" {
    /// Map a shared memory region for the edge coverage map.
    fn __afl_map_shm();
    /// Start the forkserver.
    fn __afl_start_forkserver();
    /// Start the forkserver with the hooks.
    fn __libafl_start_forkserver(hooks: *mut ());
    /// Set persistent mode
    fn __afl_set_persistent_mode(mode: u8);
}

/// Map a shared memory region for the edge coverage map.
///
/// # Note
///
/// The function's logic is written in C and this code is a wrapper.
pub fn map_shared_memory() {
    unsafe { __afl_map_shm() }
}

/// Start the forkserver from this point. Any shared memory must be created before.
///
/// # Note
///
/// The forkserver logic is written in C and this code is a wrapper.
pub fn start_forkserver() {
    unsafe { __afl_start_forkserver() }
}

/// Start the forkserver from this point. Any shared memory must be created before.
/// You must specify an object of a type implementing `ForkserverHooks`.
///
/// # Note
///
/// The forkserver logic is written in C and this code is a wrapper.
pub fn start_forkserver_with_hooks<H: ForkserverHooks>(hooks: &mut H) {
    unsafe {
        let mut c = CForkserverHooks {
            data: hooks,
            pre_fork_hook: core::mem::transmute(H::pre_fork as extern "C" fn(&mut H)),
            post_fork_hook: core::mem::transmute(
                H::post_fork as extern "C" fn(&mut H, libc::pid_t),
            ),
            iteration_start_hook: core::mem::transmute(H::iter_start as extern "C" fn(&mut H)),
            iteration_end_hook: core::mem::transmute(H::iter_end as extern "C" fn(&mut H, i32)),
        };

        __libafl_start_forkserver(core::mem::transmute((&mut c) as *mut _))
    }
}

/// Set the forkserver to persistent mode.
///
/// # Note
///
/// This sets a global behaviour
pub fn set_persistent_mode() {
    unsafe {
        __afl_set_persistent_mode(1);
    }
}
