//! Forkserver logic into targets

use core::ffi::c_int;
use std::{boxed::Box, os::raw::c_void, pin::Pin};

use libafl::Error;
use nix::{sys::wait::WaitStatus, unistd::Pid};

mod bindings {
    #![expect(non_upper_case_globals)]
    #![expect(non_camel_case_types)]
    #![expect(non_snake_case)]
    #![allow(improper_ctypes)]
    #![allow(unused_mut)]
    #![allow(unsafe_op_in_unsafe_fn)]
    #![expect(unused)]
    #![allow(unused_variables)]
    #![allow(unused_qualifications)]
    #![expect(clippy::all)]
    #![expect(clippy::pedantic)]
    #![expect(missing_docs)]

    include!(concat!(env!("OUT_DIR"), "/forkserver_bindings.rs"));
}

/// Default forkserver file descriptor.
pub use bindings::FORKSRV_FD;

/// A Forkserver Hook.
///
/// It can be given while creating a [`Forkserver`] to perform additional actions
/// during the runtime of the forkserver.
pub trait ForkserverHook: Unpin {
    /// Pre forkserver fork.
    ///
    /// There is no nothion of parent / child at this point.
    /// Thus, the actions will be common to both.
    fn pre_fork(&mut self) {}

    /// Post forkserver fork.
    ///
    /// This code is run by the *parent* just after it has been created.
    fn post_parent_fork(&mut self, _pid: Pid) {}

    /// Post forkserver fork.
    ///
    /// This code is run by the *child* just after it has been created.
    fn post_child_fork(&mut self) {}

    /// Pre parent wait.
    ///
    /// This hook is run just before the parent actually waits for the child to finish its execution.
    fn pre_parent_wait(&mut self) {}

    /// Post parent wait
    ///
    /// This hook is run just after the parent has waited for the child to finish.
    fn post_parent_wait(&mut self, _wait_status: &WaitStatus) {}
}

/// Empty forkserver hook
#[derive(Debug)]
pub struct NopForkserverHook;

impl ForkserverHook for NopForkserverHook {}

/// Driver the native forkserver implementation.
#[derive(Debug)]
pub struct Forkserver<H> {
    hook: H,
    shm_is_mapped: bool,
}

impl<H> Forkserver<H>
where
    H: ForkserverHook,
{
    extern "C" fn pre_fork_hook(fs: *mut c_void) {
        let fs = fs as *mut Self;

        unsafe {
            (*fs).hook.pre_fork();
        }
    }

    extern "C" fn post_parent_fork_hook(fs: *mut c_void, child_pid: bindings::pid_t) {
        let fs = fs as *mut Self;

        let child_pid = Pid::from_raw(child_pid);

        unsafe {
            (*fs).hook.post_parent_fork(child_pid);
        }
    }

    extern "C" fn post_child_fork_hook(fs: *mut c_void) {
        let fs = fs as *mut Self;

        unsafe {
            (*fs).hook.post_child_fork();
        }
    }

    extern "C" fn pre_parent_wait_hook(fs: *mut c_void) {
        let fs = fs as *mut Self;

        unsafe {
            (*fs).hook.pre_parent_wait();
        }
    }

    extern "C" fn post_parent_wait_hook(fs: *mut c_void, wait_pid: bindings::pid_t, status: c_int) {
        let fs = fs as *mut Self;

        let wait_pid = Pid::from_raw(wait_pid);
        let status = WaitStatus::from_raw(wait_pid, status).unwrap();

        unsafe {
            (*fs).hook.post_parent_wait(&status);
        }
    }
}

impl<H> Forkserver<H>
where
    H: ForkserverHook,
{
    /// Create a new forkserver handler
    pub fn new(hook: H) -> Pin<Box<Self>> {
        Box::pin(Self {
            hook,
            shm_is_mapped: false,
        })
    }

    /// Get a raw pointer to the forkserver hook.
    /// It is guaranteed to be pinned.
    pub fn hook_ptr_mut(self: &mut Pin<Box<Self>>) -> *mut H {
        &mut self.as_mut().get_mut().hook as *mut H
    }

    /// Map the shared map between the forkserver and the fuzzer.
    /// It uses the env variable `__AFL_SHM_ID` to know what this ID to use for the SHM.
    /// This will set `__afl_area_ptr` (pointer to the shared coverage map).
    /// The size of the shared memory must be given by `__afl_map_size` prior to calling this function.
    ///
    /// # Safety
    ///
    /// `__afl_map_size` should be set prior to calling this function.
    /// Since it's interacting with shared memory, it will have some side effects.
    /// Check the implementation of `__afl_map_shm` to check if it is compatible with your use case.
    pub unsafe fn map_shared_memory(self: &mut Pin<Box<Self>>) {
        unsafe {
            bindings::__libafl_map_shm();
        }

        self.as_mut().get_mut().shm_is_mapped = true;
    }

    /// Start the native forkserver. Any shared memory must be created before.
    /// On return, we will be in the child process, and the parent process will wait for the process to end.
    ///
    /// # Safety
    ///
    /// This function has important impact on the underlying process. Make sure to understand what it is doing
    /// prior to calling it. It is recommanded to read and understand the code of `__afl_start_forkserver`.
    pub unsafe fn start_forkserver(self: &mut Pin<Box<Self>>) -> Result<(), Error> {
        if !self.shm_is_mapped {
            return Err(Error::illegal_state(
                "Shared memory should be mapped already. `map_shared_memory` should be called prior to starting the forkserver.",
            ));
        }

        let mut fs_hook = bindings::libafl_forkserver_hook {
            data: self.as_mut().get_mut() as *mut Self as *mut c_void,

            pre_fork_hook: Some(Self::pre_fork_hook),
            post_parent_fork_hook: Some(Self::post_parent_fork_hook),
            post_child_fork_hook: Some(Self::post_child_fork_hook),
            pre_parent_wait_hook: Some(Self::pre_parent_wait_hook),
            post_parent_wait_hook: Some(Self::post_parent_wait_hook),
        };

        unsafe {
            bindings::__libafl_start_forkserver_with_hooks(
                &mut fs_hook as *mut bindings::libafl_forkserver_hook,
            );
        }

        Ok(())
    }
}
