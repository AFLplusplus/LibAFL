//! A worker-thread pool that executes many inputs concurrently and completes them out of order.

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt::{self, Debug, Formatter};
use std::{
    sync::{Mutex, MutexGuard, PoisonError, mpsc},
    thread::{self, JoinHandle},
    time::Instant,
};

use libafl_bolts::Error;

use crate::{
    executors::target::{AsyncTargetExecutor, TargetExecutor},
    fuzzer::{ExecutionObservation, ScheduledInput},
};

/// How many executions each worker may have queued ahead of it by default.
const DEFAULT_QUEUE_DEPTH_PER_WORKER: usize = 2;

/// What a worker sends back to the pool for every job it picks up.
enum WorkerReport<OT> {
    /// The input ran to completion and produced observations.
    Completed(ExecutionObservation<OT>),
    /// The worker's executor failed; the job is finished but produced no observation.
    Failed(String),
}

/// A pool of worker threads, each owning its own [`TargetExecutor`], that runs submitted inputs
/// concurrently and reports observations in completion order.
///
/// Every worker has a private executor, so targets need not be [`Sync`]: only the inputs and the
/// observations travel between threads. Observations are correlated back to their input by the
/// [`ScheduledInput::id`] handle and [`ExecutionTag`](crate::fuzzer::ExecutionTag), both of which
/// the pool copies onto the observation it emits.
pub struct ThreadPoolTargetExecutor<I, OT> {
    /// Dropped on teardown to tell the workers to exit.
    jobs: Option<mpsc::Sender<ScheduledInput<I>>>,
    reports: mpsc::Receiver<WorkerReport<OT>>,
    workers: Vec<JoinHandle<()>>,
    /// Reused buffer handed out by [`AsyncTargetExecutor::poll`] and friends.
    completed: Vec<ExecutionObservation<OT>>,
    in_flight: usize,
    capacity: usize,
}

impl<I, OT> Debug for ThreadPoolTargetExecutor<I, OT> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // The channels and join handles carry no information worth printing.
        f.debug_struct("ThreadPoolTargetExecutor")
            .field("workers", &self.workers.len())
            .field("capacity", &self.capacity)
            .field("in_flight", &self.in_flight)
            .field("collected", &self.completed.len())
            .finish_non_exhaustive()
    }
}

impl<I, OT> ThreadPoolTargetExecutor<I, OT>
where
    I: Send + 'static,
    OT: Send + 'static,
{
    /// Spawn `workers` threads, giving each the executor produced by `make_executor`.
    ///
    /// The pool accepts up to `workers * DEFAULT_QUEUE_DEPTH_PER_WORKER` in-flight executions;
    /// use [`ThreadPoolTargetExecutor::with_capacity`] to choose a different window.
    ///
    /// # Errors
    /// Returns [`Error::illegal_argument`] if `workers` is zero, or whatever `make_executor`
    /// returns if building an executor fails.
    pub fn new<E, MK>(workers: usize, make_executor: MK) -> Result<Self, Error>
    where
        E: TargetExecutor<I, OT> + Send + 'static,
        MK: FnMut(usize) -> Result<E, Error>,
    {
        Self::with_capacity(
            workers,
            workers.saturating_mul(DEFAULT_QUEUE_DEPTH_PER_WORKER),
            make_executor,
        )
    }

    /// Spawn `workers` threads and allow at most `capacity` executions in flight at once.
    ///
    /// # Errors
    /// Returns [`Error::illegal_argument`] if `workers` is zero or `capacity` is smaller than
    /// `workers`, or whatever `make_executor` returns if building an executor fails.
    pub fn with_capacity<E, MK>(
        workers: usize,
        capacity: usize,
        mut make_executor: MK,
    ) -> Result<Self, Error>
    where
        E: TargetExecutor<I, OT> + Send + 'static,
        MK: FnMut(usize) -> Result<E, Error>,
    {
        if workers == 0 {
            return Err(Error::illegal_argument(
                "a thread pool target executor needs at least one worker",
            ));
        }
        if capacity < workers {
            return Err(Error::illegal_argument(
                "a thread pool target executor needs capacity for at least one job per worker",
            ));
        }

        let (job_tx, job_rx) = mpsc::channel::<ScheduledInput<I>>();
        let (report_tx, report_rx) = mpsc::channel::<WorkerReport<OT>>();
        // `mpsc` receivers are single-consumer, so the workers share one behind a mutex. The lock
        // is only ever held across `recv`, never across a target execution.
        let job_rx = Arc::new(Mutex::new(job_rx));

        let mut handles = Vec::with_capacity(workers);
        for worker_idx in 0..workers {
            let executor = make_executor(worker_idx)?;
            let job_rx = Arc::clone(&job_rx);
            let report_tx = report_tx.clone();
            handles.push(thread::spawn(move || {
                Self::work(executor, &job_rx, &report_tx);
            }));
        }

        Ok(Self {
            jobs: Some(job_tx),
            reports: report_rx,
            workers: handles,
            completed: Vec::with_capacity(capacity),
            in_flight: 0,
            capacity,
        })
    }

    /// The worker loop: take a job, run it, report the outcome, repeat until the pool shuts down.
    fn work<E>(
        mut executor: E,
        jobs: &Mutex<mpsc::Receiver<ScheduledInput<I>>>,
        reports: &mpsc::Sender<WorkerReport<OT>>,
    ) where
        E: TargetExecutor<I, OT>,
    {
        loop {
            let job = match Self::lock(jobs).recv() {
                Ok(job) => job,
                // The pool was dropped; no more work will arrive.
                Err(mpsc::RecvError) => return,
            };

            let started = Instant::now();
            let report = match executor.execute_input(&job.input) {
                Ok(mut observation) => {
                    observation.id = Some(job.id);
                    observation.tag = job.tag;
                    if observation.exec_time.is_none() {
                        observation.exec_time = Some(started.elapsed());
                    }
                    WorkerReport::Completed(observation)
                }
                Err(err) => WorkerReport::Failed(err.to_string()),
            };

            if let Err(mpsc::SendError(_)) = reports.send(report) {
                // The pool was dropped while we were executing; nothing left to report to.
                return;
            }
        }
    }

    /// Lock the shared job receiver, recovering the guard if another worker panicked.
    ///
    /// A poisoned lock here only means some worker unwound; the receiver itself is still usable,
    /// so the remaining workers keep draining the queue instead of cascading the panic.
    fn lock(
        jobs: &Mutex<mpsc::Receiver<ScheduledInput<I>>>,
    ) -> MutexGuard<'_, mpsc::Receiver<ScheduledInput<I>>> {
        jobs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of worker threads in this pool.
    #[must_use]
    pub fn workers(&self) -> usize {
        self.workers.len()
    }

    /// Move a worker report into the completion buffer, or surface its failure.
    fn accept(&mut self, report: WorkerReport<OT>) -> Result<(), Error> {
        self.in_flight -= 1;
        match report {
            WorkerReport::Completed(observation) => {
                self.completed.push(observation);
                Ok(())
            }
            WorkerReport::Failed(message) => Err(Error::unknown(message)),
        }
    }

    /// Drain everything the workers have already reported, without blocking.
    fn accept_ready(&mut self) -> Result<(), Error> {
        loop {
            match self.reports.try_recv() {
                Ok(report) => self.accept(report)?,
                Err(mpsc::TryRecvError::Empty) => return Ok(()),
                Err(mpsc::TryRecvError::Disconnected) => return Err(Self::workers_gone()),
            }
        }
    }

    /// Block for exactly one report.
    fn accept_one(&mut self) -> Result<(), Error> {
        match self.reports.recv() {
            Ok(report) => self.accept(report),
            Err(mpsc::RecvError) => Err(Self::workers_gone()),
        }
    }

    fn workers_gone() -> Error {
        Error::illegal_state("every thread pool worker has exited; the pool can no longer execute")
    }
}

impl<I, OT> AsyncTargetExecutor<I, OT> for ThreadPoolTargetExecutor<I, OT>
where
    I: Send + 'static,
    OT: Send + 'static,
{
    fn capacity(&self) -> usize {
        self.capacity
    }

    fn in_flight(&self) -> usize {
        self.in_flight
    }

    fn submit(&mut self, scheduled: ScheduledInput<I>) -> Result<(), Error> {
        if self.in_flight >= self.capacity {
            return Err(Error::illegal_state(
                "thread pool target executor is at capacity; collect observations before submitting",
            ));
        }
        let Some(jobs) = self.jobs.as_ref() else {
            return Err(Self::workers_gone());
        };
        jobs.send(scheduled).map_err(|_| Self::workers_gone())?;
        self.in_flight += 1;
        Ok(())
    }

    fn poll(&mut self) -> Result<&[ExecutionObservation<OT>], Error> {
        self.completed.clear();
        self.accept_ready()?;
        Ok(&self.completed)
    }

    fn wait(&mut self) -> Result<&[ExecutionObservation<OT>], Error> {
        self.completed.clear();
        if self.in_flight > 0 {
            self.accept_one()?;
            self.accept_ready()?;
        }
        Ok(&self.completed)
    }

    fn drain(&mut self) -> Result<&[ExecutionObservation<OT>], Error> {
        self.completed.clear();
        while self.in_flight > 0 {
            self.accept_one()?;
        }
        Ok(&self.completed)
    }
}

impl<I, OT> Drop for ThreadPoolTargetExecutor<I, OT> {
    fn drop(&mut self) {
        // Closing the job channel is what tells the workers to return.
        self.jobs = None;
        for worker in self.workers.drain(..) {
            if let Err(panic) = worker.join() {
                log::error!("a thread pool target executor worker panicked: {panic:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};
    use core::time::Duration;

    use libafl_bolts::{Error, rands::StdRand, tuples::tuple_list};

    use super::{DEFAULT_QUEUE_DEPTH_PER_WORKER, ThreadPoolTargetExecutor};
    use crate::{
        corpus::{Corpus, InMemoryCorpus, Testcase},
        events::NopEventManager,
        executors::{
            ExitKind,
            target::{AsyncFuzzLoop, AsyncTargetExecutor, TargetExecutor},
        },
        feedbacks::ConstFeedback,
        fuzzer::{
            ExecutionMode, ExecutionObservation, ExecutionRequest, ExecutionTag, ScheduledInput,
            StdFuzzer,
        },
        inputs::BytesInput,
        mutators::{mutations::BitFlipMutator, scheduled::HavocScheduledMutator},
        schedulers::{QueueScheduler, Scheduler},
        stages::push::StdMutationalPushStage,
        state::{HasExecutions, HasInFlightExecutions, StdState},
    };

    /// An executor that sleeps for as many milliseconds as the first input byte says, so that
    /// completions are forced out of submission order.
    #[derive(Debug)]
    struct SleepyExecutor {
        observations: Vec<ExecutionObservation<u8>>,
    }

    impl TargetExecutor<BytesInput, u8> for SleepyExecutor {
        fn execute_input(&mut self, input: &BytesInput) -> Result<ExecutionObservation<u8>, Error> {
            let millis = u64::from(input.as_ref().first().copied().unwrap_or(0));
            std::thread::sleep(Duration::from_millis(millis));
            Ok(ExecutionObservation::new(ExitKind::Ok, millis as u8))
        }

        fn execute_batch<'a>(
            &'a mut self,
            inputs: &[BytesInput],
        ) -> Result<&'a [ExecutionObservation<u8>], Error> {
            self.observations.clear();
            for input in inputs {
                let observation = self.execute_input(input)?;
                self.observations.push(observation);
            }
            Ok(&self.observations)
        }

        fn execute_borrowed_batch<'a>(
            &'a mut self,
            inputs: &[&BytesInput],
        ) -> Result<&'a [ExecutionObservation<u8>], Error> {
            self.observations.clear();
            for input in inputs {
                let observation = self.execute_input(input)?;
                self.observations.push(observation);
            }
            Ok(&self.observations)
        }

        fn execute_request<'a>(
            &'a mut self,
            request: &ExecutionRequest<BytesInput>,
        ) -> Result<&'a [ExecutionObservation<u8>], Error> {
            self.execute_batch(request.inputs.as_slice())
        }
    }

    /// An executor that always fails, to check the failure path reaches the caller.
    #[derive(Debug)]
    struct BrokenExecutor;

    impl TargetExecutor<BytesInput, u8> for BrokenExecutor {
        fn execute_input(
            &mut self,
            _input: &BytesInput,
        ) -> Result<ExecutionObservation<u8>, Error> {
            Err(Error::unknown("target is unavailable"))
        }

        fn execute_batch<'a>(
            &'a mut self,
            _inputs: &[BytesInput],
        ) -> Result<&'a [ExecutionObservation<u8>], Error> {
            Err(Error::unknown("target is unavailable"))
        }

        fn execute_borrowed_batch<'a>(
            &'a mut self,
            _inputs: &[&BytesInput],
        ) -> Result<&'a [ExecutionObservation<u8>], Error> {
            Err(Error::unknown("target is unavailable"))
        }

        fn execute_request<'a>(
            &'a mut self,
            _request: &ExecutionRequest<BytesInput>,
        ) -> Result<&'a [ExecutionObservation<u8>], Error> {
            Err(Error::unknown("target is unavailable"))
        }
    }

    fn scheduled(id: u64, sleep_millis: u8, mode: ExecutionMode) -> ScheduledInput<BytesInput> {
        ScheduledInput {
            id,
            tag: Some(ExecutionTag::new(0, id).with_mode(mode)),
            input: BytesInput::new(vec![sleep_millis]),
        }
    }

    fn sleepy_pool(workers: usize) -> ThreadPoolTargetExecutor<BytesInput, u8> {
        ThreadPoolTargetExecutor::new(workers, |_| {
            Ok(SleepyExecutor {
                observations: Vec::new(),
            })
        })
        .unwrap()
    }

    #[test]
    fn default_capacity_scales_with_workers() {
        let pool = sleepy_pool(3);
        assert_eq!(pool.workers(), 3);
        assert_eq!(pool.capacity(), 3 * DEFAULT_QUEUE_DEPTH_PER_WORKER);
        assert_eq!(pool.free_capacity(), pool.capacity());
    }

    #[test]
    fn rejects_degenerate_configuration() {
        let zero_workers =
            ThreadPoolTargetExecutor::<BytesInput, u8>::new(0, |_| Ok(BrokenExecutor));
        assert!(zero_workers.is_err());

        let too_small =
            ThreadPoolTargetExecutor::<BytesInput, u8>::with_capacity(2, 1, |_| Ok(BrokenExecutor));
        assert!(too_small.is_err());
    }

    #[test]
    fn completes_out_of_order_and_preserves_handles() {
        let mut pool = sleepy_pool(4);

        // Submitted slowest first, so a correct pool reports them roughly in reverse.
        for (offset, millis) in [60_u8, 40, 20, 1].into_iter().enumerate() {
            pool.submit(scheduled(offset as u64 + 1, millis, ExecutionMode::CmpLog))
                .unwrap();
        }
        assert_eq!(pool.in_flight(), 4);

        let mut seen = Vec::new();
        while pool.in_flight() > 0 {
            for observation in pool.wait().unwrap() {
                let id = observation
                    .id
                    .expect("every observation carries its handle");
                let tag = observation.tag.expect("every observation carries its tag");
                assert_eq!(tag.input_id, id);
                assert_eq!(tag.mode, ExecutionMode::CmpLog);
                assert!(observation.exec_time.is_some());
                seen.push(id);
            }
        }

        seen.sort_unstable();
        assert_eq!(seen, vec![1, 2, 3, 4]);
    }

    #[test]
    fn submitting_beyond_capacity_is_rejected() {
        let mut pool = ThreadPoolTargetExecutor::<BytesInput, u8>::with_capacity(1, 1, |_| {
            Ok(SleepyExecutor {
                observations: Vec::new(),
            })
        })
        .unwrap();

        pool.submit(scheduled(1, 20, ExecutionMode::Normal))
            .unwrap();
        assert!(pool.submit(scheduled(2, 0, ExecutionMode::Normal)).is_err());

        assert_eq!(pool.drain().unwrap().len(), 1);
        assert_eq!(pool.in_flight(), 0);
        pool.submit(scheduled(2, 0, ExecutionMode::Normal)).unwrap();
        assert_eq!(pool.drain().unwrap().len(), 1);
    }

    #[test]
    fn poll_never_blocks_and_drain_collects_everything() {
        let mut pool = sleepy_pool(2);
        for id in 1..=4 {
            pool.submit(scheduled(id, 10, ExecutionMode::Normal))
                .unwrap();
        }

        // `poll` is allowed to come back empty while the workers are still busy.
        let polled = pool.poll().unwrap().len();
        assert!(polled <= 4);

        let drained = pool.drain().unwrap().len();
        assert_eq!(polled + drained, 4);
        assert_eq!(pool.in_flight(), 0);
    }

    #[test]
    fn waiting_with_nothing_in_flight_returns_immediately() {
        let mut pool = sleepy_pool(1);
        assert!(pool.wait().unwrap().is_empty());
        assert!(pool.drain().unwrap().is_empty());
    }

    /// An executor that produces an empty observers tuple, for driving a real engine end to end.
    #[derive(Debug)]
    struct NopObservationExecutor {
        observations: Vec<ExecutionObservation<()>>,
    }

    impl NopObservationExecutor {
        fn new() -> Self {
            Self {
                observations: Vec::new(),
            }
        }

        fn observe(&mut self, count: usize) -> &[ExecutionObservation<()>] {
            self.observations.clear();
            for _ in 0..count {
                self.observations
                    .push(ExecutionObservation::new(ExitKind::Ok, ()));
            }
            &self.observations
        }
    }

    impl TargetExecutor<BytesInput, ()> for NopObservationExecutor {
        fn execute_input(
            &mut self,
            _input: &BytesInput,
        ) -> Result<ExecutionObservation<()>, Error> {
            Ok(ExecutionObservation::new(ExitKind::Ok, ()))
        }

        fn execute_batch<'a>(
            &'a mut self,
            inputs: &[BytesInput],
        ) -> Result<&'a [ExecutionObservation<()>], Error> {
            Ok(self.observe(inputs.len()))
        }

        fn execute_borrowed_batch<'a>(
            &'a mut self,
            inputs: &[&BytesInput],
        ) -> Result<&'a [ExecutionObservation<()>], Error> {
            Ok(self.observe(inputs.len()))
        }

        fn execute_request<'a>(
            &'a mut self,
            request: &ExecutionRequest<BytesInput>,
        ) -> Result<&'a [ExecutionObservation<()>], Error> {
            Ok(self.observe(request.inputs.len()))
        }
    }

    #[test]
    fn async_fuzz_loop_keeps_the_pool_busy_and_reports_every_execution() {
        const OBSERVATION_BUDGET: u64 = 128;

        let mut corpus = InMemoryCorpus::<BytesInput>::new();
        let seed = corpus
            .add(Testcase::new(BytesInput::new(vec![b'a', b'b', b'c', b'd'])))
            .unwrap();

        let mut feedback = ConstFeedback::new(false);
        let mut objective = ConstFeedback::new(false);
        let mut state = StdState::new(
            StdRand::with_seed(0xC0FFEE),
            corpus,
            InMemoryCorpus::new(),
            &mut feedback,
            &mut objective,
        )
        .unwrap();

        let mut scheduler = QueueScheduler::new();
        Scheduler::<BytesInput, _>::on_add(&mut scheduler, &mut state, seed).unwrap();

        let mut fuzzer = StdFuzzer::new(
            scheduler,
            ConstFeedback::new(false),
            ConstFeedback::new(false),
            tuple_list!(StdMutationalPushStage::new(HavocScheduledMutator::new(
                tuple_list!(BitFlipMutator::new())
            ))),
        );
        let mut manager = NopEventManager::new();

        let mut pool = ThreadPoolTargetExecutor::<BytesInput, ()>::new(4, |_| {
            Ok(NopObservationExecutor::new())
        })
        .unwrap();

        let reported = AsyncFuzzLoop::run_for(
            &mut fuzzer,
            &mut pool,
            &mut state,
            &mut manager,
            Some(OBSERVATION_BUDGET),
        )
        .unwrap();

        assert!(
            reported >= OBSERVATION_BUDGET,
            "the loop must report at least its budget, reported {reported}"
        );
        assert_eq!(
            pool.in_flight(),
            0,
            "the loop must not leave executions in flight"
        );
        assert_eq!(
            state.active_inputs_count(),
            0,
            "every handed-out input must be retired once its observation is reported"
        );
        assert_eq!(*state.executions(), reported);
    }

    #[test]
    fn executor_failures_reach_the_caller() {
        let mut pool =
            ThreadPoolTargetExecutor::<BytesInput, u8>::new(1, |_| Ok(BrokenExecutor)).unwrap();
        pool.submit(scheduled(1, 0, ExecutionMode::Normal)).unwrap();
        assert!(pool.drain().is_err());
        assert_eq!(pool.in_flight(), 0);
    }
}
