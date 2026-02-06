//! Multi-threaded launcher for `TinyInst` fuzzing
//!
//! This module provides [`TinyInstLauncher`], a multi-threaded launcher that
//! spawns multiple fuzzing threads with shared state for corpus and coverage.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    collections::HashSet,
    sync::RwLock,
    thread::{self, JoinHandle},
};

use libafl::Error;

/// Shared state between fuzzing threads
#[derive(Debug)]
pub struct SharedState<C> {
    /// Shared corpus protected by `RwLock`
    pub corpus: Arc<RwLock<C>>,
    /// Shared cumulative coverage set
    pub coverage: Arc<RwLock<HashSet<u64>>>,
}

impl<C> SharedState<C> {
    /// Create a new shared state with the given corpus
    pub fn new(corpus: C) -> Self {
        Self {
            corpus: Arc::new(RwLock::new(corpus)),
            coverage: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Get a clone of the corpus Arc
    #[must_use]
    pub fn corpus_arc(&self) -> Arc<RwLock<C>> {
        Arc::clone(&self.corpus)
    }

    /// Get a clone of the coverage Arc
    #[must_use]
    pub fn coverage_arc(&self) -> Arc<RwLock<HashSet<u64>>> {
        Arc::clone(&self.coverage)
    }

    /// Get the current coverage count
    #[must_use]
    pub fn coverage_count(&self) -> usize {
        self.coverage.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Add new coverage offsets
    pub fn add_coverage(&self, offsets: &[u64]) {
        if let Ok(mut cov) = self.coverage.write() {
            for &offset in offsets {
                cov.insert(offset);
            }
        }
    }
}

impl<C> Clone for SharedState<C> {
    fn clone(&self) -> Self {
        Self {
            corpus: Arc::clone(&self.corpus),
            coverage: Arc::clone(&self.coverage),
        }
    }
}

/// Builder for [`TinyInstLauncher`]
#[derive(Debug)]
pub struct TinyInstLauncherBuilder<F> {
    num_threads: usize,
    launch_delay: Duration,
    client_fn: Option<F>,
}

impl<F> Default for TinyInstLauncherBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F> TinyInstLauncherBuilder<F> {
    /// Create a new launcher builder with default settings
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_threads: 1,
            launch_delay: Duration::from_millis(100),
            client_fn: None,
        }
    }

    /// Set the number of threads to spawn
    #[must_use]
    pub fn num_threads(mut self, num_threads: usize) -> Self {
        self.num_threads = num_threads;
        self
    }

    /// Set the delay between launching threads
    #[must_use]
    pub fn launch_delay(mut self, delay: Duration) -> Self {
        self.launch_delay = delay;
        self
    }

    /// Set the client function that each thread will run
    ///
    /// The function receives the thread ID (0-indexed) as an argument
    #[must_use]
    pub fn run_client(mut self, client_fn: F) -> Self {
        self.client_fn = Some(client_fn);
        self
    }

    /// Build the launcher
    pub fn build(self) -> Result<TinyInstLauncher<F>, Error> {
        let client_fn = self
            .client_fn
            .ok_or_else(|| Error::illegal_argument("Client function must be set"))?;

        Ok(TinyInstLauncher {
            num_threads: self.num_threads,
            launch_delay: self.launch_delay,
            client_fn,
        })
    }
}

/// Multi-threaded launcher for `TinyInst` fuzzing
///
/// Spawns multiple fuzzing threads that can share state through
/// [`SharedState`]. Each thread runs the provided client function
/// with its thread ID.
///
/// # Example
///
/// ```ignore
/// use libafl_tinyinst::launcher::TinyInstLauncher;
/// use std::time::Duration;
///
/// let launcher = TinyInstLauncher::builder()
///     .num_threads(4)
///     .launch_delay(Duration::from_millis(100))
///     .run_client(|thread_id| {
///         println!("Thread {} starting", thread_id);
///         // Setup and run fuzzer...
///         Ok(())
///     })
///     .build()?;
///
/// launcher.launch_and_wait()?;
/// ```
#[derive(Debug)]
pub struct TinyInstLauncher<F> {
    num_threads: usize,
    launch_delay: Duration,
    client_fn: F,
}

impl<F> TinyInstLauncher<F> {
    /// Create a new builder for the launcher
    #[must_use]
    pub fn builder() -> TinyInstLauncherBuilder<F> {
        TinyInstLauncherBuilder::new()
    }
}

impl<F, R> TinyInstLauncher<F>
where
    F: Fn(usize) -> Result<R, Error> + Send + Sync + Clone + 'static,
    R: Send + 'static,
{
    /// Launch all threads and wait for them to complete
    ///
    /// Returns a vector of results from each thread, or the first error encountered.
    pub fn launch_and_wait(self) -> Result<Vec<R>, Error> {
        let mut handles: Vec<JoinHandle<Result<R, Error>>> = Vec::with_capacity(self.num_threads);

        for thread_id in 0..self.num_threads {
            let client_fn = self.client_fn.clone();

            let handle = thread::spawn(move || client_fn(thread_id));

            handles.push(handle);

            // Delay before launching next thread (except for the last one)
            if thread_id < self.num_threads - 1 {
                thread::sleep(self.launch_delay);
            }
        }

        // Wait for all threads and collect results
        let mut results = Vec::with_capacity(self.num_threads);
        for (thread_id, handle) in handles.into_iter().enumerate() {
            match handle.join() {
                Ok(result) => match result {
                    Ok(r) => results.push(r),
                    Err(e) => {
                        return Err(Error::unknown(format!(
                            "Thread {thread_id} returned error: {e}"
                        )));
                    }
                },
                Err(_) => {
                    return Err(Error::unknown(format!("Thread {thread_id} panicked")));
                }
            }
        }

        Ok(results)
    }

    /// Launch all threads without waiting
    ///
    /// Returns the thread handles so the caller can manage them manually.
    #[must_use]
    pub fn launch(self) -> Vec<JoinHandle<Result<R, Error>>> {
        let mut handles: Vec<JoinHandle<Result<R, Error>>> = Vec::with_capacity(self.num_threads);

        for thread_id in 0..self.num_threads {
            let client_fn = self.client_fn.clone();

            let handle = thread::spawn(move || client_fn(thread_id));

            handles.push(handle);

            // Delay before launching next thread (except for the last one)
            if thread_id < self.num_threads - 1 {
                thread::sleep(self.launch_delay);
            }
        }

        handles
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn test_shared_state() {
        let state: SharedState<Vec<String>> = SharedState::new(vec!["test".to_string()]);

        // Test coverage tracking
        state.add_coverage(&[0x1000, 0x2000, 0x3000]);
        assert_eq!(state.coverage_count(), 3);

        // Add duplicate
        state.add_coverage(&[0x1000]);
        assert_eq!(state.coverage_count(), 3);

        // Add new
        state.add_coverage(&[0x4000]);
        assert_eq!(state.coverage_count(), 4);
    }

    #[test]
    fn test_launcher_single_thread() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let launcher = TinyInstLauncher::builder()
            .num_threads(1)
            .run_client(move |thread_id| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(thread_id)
            })
            .build()
            .unwrap();

        let results = launcher.launch_and_wait().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], 0);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_launcher_multiple_threads() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        let launcher = TinyInstLauncher::builder()
            .num_threads(4)
            .launch_delay(Duration::from_millis(10))
            .run_client(move |thread_id| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
                Ok(thread_id)
            })
            .build()
            .unwrap();

        let results = launcher.launch_and_wait().unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(counter.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn test_launcher_error_handling() {
        let launcher = TinyInstLauncher::builder()
            .num_threads(2)
            .run_client(|thread_id| {
                if thread_id == 1 {
                    Err(Error::unknown("Test error"))
                } else {
                    Ok(thread_id)
                }
            })
            .build()
            .unwrap();

        let result = launcher.launch_and_wait();
        assert!(result.is_err());
    }
}
