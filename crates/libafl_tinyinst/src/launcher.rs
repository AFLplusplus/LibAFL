//! Multi-threaded launcher for `TinyInst` fuzzing
//!
//! This module provides [`TinyInstLauncher`] for spawning multiple fuzzing threads
//! and [`SharedCorpusQueue`] for sharing corpus entries between threads.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    collections::VecDeque,
    sync::Mutex,
    thread::{self, JoinHandle},
};

use libafl::{Error, inputs::Input};

/// Shared corpus queue for distributing testcases between fuzzing threads
///
/// Each thread can push new interesting testcases to the queue, and
/// periodically pull testcases discovered by other threads.
#[derive(Debug, Clone)]
pub struct SharedCorpusQueue<I> {
    queue: Arc<Mutex<VecDeque<I>>>,
}

impl<I> SharedCorpusQueue<I>
where
    I: Input,
{
    /// Create a new empty shared corpus queue
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Push a new testcase to the queue for other threads to discover
    pub fn push(&self, input: I) {
        if let Ok(mut queue) = self.queue.lock() {
            queue.push_back(input);
        }
    }

    /// Try to pop a testcase from the queue (non-blocking)
    ///
    /// Returns `None` if the queue is empty or lock fails
    #[must_use]
    pub fn pop(&self) -> Option<I> {
        self.queue.lock().ok()?.pop_front()
    }

    /// Drain all testcases from the queue
    ///
    /// Returns a vector of all pending testcases
    #[must_use]
    pub fn drain(&self) -> Vec<I> {
        if let Ok(mut queue) = self.queue.lock() {
            queue.drain(..).collect()
        } else {
            Vec::new()
        }
    }

    /// Get the current queue length
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Check if the queue is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<I> Default for SharedCorpusQueue<I>
where
    I: Input,
{
    fn default() -> Self {
        Self::new()
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
/// Spawns multiple fuzzing threads, each running the provided client function
/// with its thread ID. Each thread maintains its own independent fuzzer state.
///
/// For sharing corpus entries between threads, use [`SharedCorpusQueue`]:
/// each thread can push new testcases and pull testcases from other threads.
///
/// # Example
///
/// ```ignore
/// use libafl_tinyinst::launcher::{TinyInstLauncher, SharedCorpusQueue};
/// use libafl::inputs::BytesInput;
/// use std::time::Duration;
///
/// let shared_queue = SharedCorpusQueue::<BytesInput>::new();
///
/// let launcher = TinyInstLauncher::builder()
///     .num_threads(4)
///     .launch_delay(Duration::from_millis(100))
///     .run_client(|thread_id| {
///         let queue = shared_queue.clone();
///         // In your fuzzer loop:
///         // - When finding new testcase: queue.push(input)
///         // - Periodically: for input in queue.drain() { add to corpus }
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
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

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
