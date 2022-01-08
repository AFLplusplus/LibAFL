//! the ``StacktraceObserver`` looks up the stacktrace on the execution thread and computes a hash for it for dedupe

use crate::{bolts::tuples::Named, observers::Observer, Error};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub static mut LOCAL_HASH: u64 = 0;

/// An observer looking at the stacktrace if a run crashes (For rust code)
pub mod stacktrace_hooks {
    use crate::executors::inprocess::BACKTRACE_SHMEM_DATA;
    use crate::observers::LOCAL_HASH;
    use ahash::AHasher;
    use backtrace::Backtrace;
    use std::hash::Hasher;
    use std::panic;

    pub fn collect_backtrace() {
        let b = Backtrace::new();
        let trace = format!("{:?}", b);
        eprintln!("{}", trace);
        let mut hasher = AHasher::new_with_keys(0, 0);
        hasher.write(trace.as_bytes());
        let hash = hasher.finish();
        println!("backtrace collected with hash={}", hash);
        unsafe {
            // If run with InProcessForkExecutor
            if BACKTRACE_SHMEM_DATA.is_ready() {
                BACKTRACE_SHMEM_DATA.store_stacktrace_hash(hash);
            }
            // if run with InProcessExecutor
            LOCAL_HASH = hash;
        }
    }

    pub fn setup_rust_panic_hook() {
        panic::set_hook(Box::new(|_panic_info| {
            collect_backtrace();
        }));
    }

    pub unsafe fn register_bt_collection_in_signal_handler() {
        crate::executors::inprocess::COLLECT_BACKTRACE = true;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum HarnessType {
    RUST,
    FFI,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StacktraceObserver {
    observer_name: String,
    harness_type: HarnessType,
    hash: Option<u64>,
}

impl StacktraceObserver {
    /// Creates a new [`StacktraceObserver`] with the given name.
    #[must_use]
    pub fn new(observer_name: String, harness_type: HarnessType) -> Self {
        println!("panic hook is being set");
        match harness_type {
            HarnessType::RUST => stacktrace_hooks::setup_rust_panic_hook(),
            HarnessType::FFI => unsafe {
                stacktrace_hooks::register_bt_collection_in_signal_handler()
            },
        }
        Self {
            observer_name,
            harness_type,
            hash: None,
        }
    }

    /// Gets the hash value of this observer.
    #[must_use]
    pub fn hash(&self) -> &Option<u64> {
        &self.hash
    }

    /// Updates the hash value of this observer.
    pub fn update_hash(&mut self, hash: u64) {
        self.hash = Some(hash);
    }

    pub fn clear_hash(&mut self) {
        self.hash = None;
    }
}

impl Default for StacktraceObserver {
    fn default() -> Self {
        Self::new("StacktraceObserver".to_string(), HarnessType::RUST)
    }
}

impl<I, S> Observer<I, S> for StacktraceObserver
where
    I: Debug,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        unsafe {
            // Makes sense only when run with an InProcessExecutor
            if LOCAL_HASH > 0 {
                self.update_hash(LOCAL_HASH);
                LOCAL_HASH = 0;
            }
        }
        Ok(())
    }
}

impl Named for StacktraceObserver {
    fn name(&self) -> &str {
        &self.observer_name
    }
}
