use core::{ffi::c_void, fmt::Debug};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libafl::{
    bolts::tuples::Named,
    events::EventFirer,
    executors::ExitKind,
    feedbacks::Feedback,
    inputs::UsesInput,
    observers::{Observer, ObserversTuple},
    state::HasClientPerfMonitor,
    Error,
};
use serde::{Deserialize, Serialize};

use crate::sanitizer_ifaces::__sanitizer_install_malloc_and_free_hooks;

extern "C" {
    fn libafl_check_malloc_size(ptr: *const c_void) -> usize;
}

static OOMED: AtomicBool = AtomicBool::new(false);
static mut RSS_MAX: usize = 2 << 30; // 2GB, which is a typical default

static MALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);

extern "C" fn oom_malloc_hook(ptr: *const c_void, size: usize) {
    let size = match unsafe { libafl_check_malloc_size(ptr) } {
        0 => size,
        real => real,
    };

    let total = MALLOC_SIZE.fetch_add(size, Ordering::Relaxed) + size;
    if total > unsafe { RSS_MAX } {
        OOMED.store(true, Ordering::Relaxed);
        unsafe {
            // we need to kill the process in a way that immediately triggers the crash handler
            libc::abort();
        }
    }
}

extern "C" fn oom_free_hook(ptr: *const c_void) {
    let size = unsafe { libafl_check_malloc_size(ptr) };
    if MALLOC_SIZE
        .fetch_sub(size, Ordering::Relaxed)
        .checked_sub(size)
        .is_none()
    {
        panic!("We somehow freed more memory than was available on the system!");
    }
}

const OOM_OBS_NAME: &str = "libfuzzer-like-oom";

#[derive(Debug, Serialize, Deserialize)]
pub struct OOMObserver {
    oomed: bool,
}

impl OOMObserver {
    pub fn new(rss_max: usize) -> Self {
        unsafe {
            RSS_MAX = rss_max;
            __sanitizer_install_malloc_and_free_hooks(Some(oom_malloc_hook), Some(oom_free_hook));
        }
        Self { oomed: false }
    }
}

impl Named for OOMObserver {
    fn name(&self) -> &str {
        OOM_OBS_NAME
    }
}

impl<S> Observer<S> for OOMObserver
where
    S: UsesInput,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &S::Input) -> Result<(), Error> {
        OOMED.store(false, Ordering::Relaxed);
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &S::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.oomed = OOMED.load(Ordering::Relaxed);
        Ok(())
    }

    fn pre_exec_child(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.pre_exec(state, input)
    }

    fn post_exec_child(
        &mut self,
        state: &mut S,
        input: &S::Input,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.post_exec(state, input, exit_kind)
    }
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, Default)]
pub struct OOMFeedback;

impl Named for OOMFeedback {
    fn name(&self) -> &str {
        "oom"
    }
}

impl<S> Feedback<S> for OOMFeedback
where
    S: UsesInput + HasClientPerfMonitor,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        Ok(OOMED.load(Ordering::Relaxed))
    }
}
