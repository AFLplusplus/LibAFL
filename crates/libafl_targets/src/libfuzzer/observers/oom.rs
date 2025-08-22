use alloc::borrow::Cow;
use core::{
    ffi::c_void,
    fmt::Debug,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use libafl::{
    Error,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
    observers::Observer,
};
use libafl_bolts::Named;
use libc::SIGABRT;
use serde::{Deserialize, Serialize};

unsafe extern "C" {
    fn libafl_check_malloc_size(ptr: *const c_void) -> usize;
}

static RUNNING: AtomicBool = AtomicBool::new(false);
static OOMED: AtomicBool = AtomicBool::new(false);
static RSS_MAX: AtomicUsize = AtomicUsize::new(2 << 30);
// 2GB, which is the default
static MALLOC_MAX: AtomicUsize = AtomicUsize::new(2 << 30);

static MALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);

/// malloc hook which will be invoked if address sanitizer is present. Used to detect if the target makes a malloc call
/// that will exceed the permissible size
///
/// # Safety
/// Is only safe to call with valid freshly allocated pointers backed by allocations of `size`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_malloc_hook(ptr: *const c_void, size: usize) {
    if RUNNING.load(Ordering::Relaxed) {
        let size = match unsafe { libafl_check_malloc_size(ptr) } {
            0 => size, // either the malloc size function didn't work or it's really zero-sized
            real => real,
        };

        let total = MALLOC_SIZE.fetch_add(size, Ordering::Relaxed) + size;
        if (size > MALLOC_MAX.load(Ordering::Relaxed) || total > RSS_MAX.load(Ordering::Relaxed))
            && !OOMED.swap(true, Ordering::Relaxed)
        {
            unsafe {
                // we need to kill the process in a way that immediately triggers the crash handler
                libc::raise(SIGABRT);
            }
        }
    }
}

/// free hook which will be invoked if ASAN is present. Used to detect if the target makes a malloc call that will
/// exceed the permissible size
///
/// # Safety
/// Is only safe to call with valid allocated pointers, about to be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_free_hook(ptr: *const c_void) {
    if RUNNING.load(Ordering::Relaxed) {
        let size = unsafe { libafl_check_malloc_size(ptr) };
        MALLOC_SIZE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |existing| {
                Some(existing.saturating_sub(size))
            })
            .expect("must complete successfully");
    }
}

static OOM_OBS_NAME: Cow<'static, str> = Cow::Borrowed("libfuzzer-like-oom");

/// Observer which detects if the target would run out of memory or otherwise violate the permissible usage of malloc
#[derive(Debug, Serialize, Deserialize)]
pub struct OomObserver {
    oomed: bool,
}

impl OomObserver {
    /// Create a [`OomObserver`] with the provided `rss_max` (total heap size) and `malloc_max` (largest permissible malloc
    /// allocation size)
    pub fn new(rss_max: usize, malloc_max: usize) -> Self {
        RSS_MAX.store(rss_max, Ordering::Relaxed);
        MALLOC_MAX.store(malloc_max, Ordering::Relaxed);
        Self { oomed: false }
    }
}

impl Named for OomObserver {
    // strictly one name to prevent two from being registered
    fn name(&self) -> &Cow<'static, str> {
        &OOM_OBS_NAME
    }
}

impl<I, S> Observer<I, S> for OomObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        OOMED.store(false, Ordering::Relaxed);
        // must reset for platforms which do not offer malloc tracking
        MALLOC_SIZE.store(0, Ordering::Relaxed);
        RUNNING.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        RUNNING.store(false, Ordering::Relaxed);
        self.oomed = OOMED.load(Ordering::Relaxed);
        Ok(())
    }

    fn pre_exec_child(&mut self, state: &mut S, input: &I) -> Result<(), Error> {
        self.pre_exec(state, input)
    }

    fn post_exec_child(
        &mut self,
        state: &mut S,
        input: &I,
        exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        self.post_exec(state, input, exit_kind)
    }
}

/// Feedback for the similarly named [`OomObserver`] to detect if the target crashed due to an observed OOM
#[derive(Debug, Serialize, Deserialize, Copy, Clone, Default)]
pub struct OomFeedback;

impl OomFeedback {
    /// Whether the target OOM'd in the last execution
    pub fn oomed() -> bool {
        OOMED.load(Ordering::Relaxed)
    }
}

impl Named for OomFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("oom");
        &NAME
    }
}

impl<S> StateInitializer<S> for OomFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for OomFeedback {
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(Self::oomed())
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(Self::oomed())
    }
}
