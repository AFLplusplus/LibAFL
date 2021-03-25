use crate::{
    corpus::CorpusScheduler,
    events::{Event, EventManager},
    executors::{Executor, HasObservers},
    inputs::Input,
    observers::ObserversTuple,
    stages::StagesTuple,
    state::HasExecutions,
    utils::current_time,
    Error,
};

use alloc::string::ToString;
use core::{marker::PhantomData, time::Duration};

/// Send a stats update all 6 (or more) seconds
const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_millis(6 * 1000);

/// Holds a set of stages
pub trait HasStages<CS, E, EM, I, S, ST>
where
    ST: StagesTuple<CS, E, EM, I, S>,
    E: Executor<I>,
    EM: EventManager<I, S>,
    I: Input,
    Self: Sized,
{
    fn stages(&self) -> &ST;

    fn stages_mut(&mut self) -> &mut ST;
}

/// Holds a scheduler
pub trait HasCorpusScheduler<CS, I, S>
where
    CS: CorpusScheduler<I, S>,
    I: Input,
{
    fn scheduler(&self) -> &CS;

    fn scheduler_mut(&mut self) -> &mut CS;
}

/// The main fuzzer trait.
pub trait Fuzzer<E, EM, S, CS> {
    /// Fuzz for a single iteration
    /// Returns the index of the last fuzzed corpus item
    fn fuzz_one(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
    ) -> Result<usize, Error>;

    /// Fuzz forever (or until stopped)
    fn fuzz_loop(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
    ) -> Result<usize, Error> {
        let mut last = current_time();
        let stats_timeout = STATS_TIMEOUT_DEFAULT;
        loop {
            self.fuzz_one(state, executor, manager, scheduler)?;
            last = Self::maybe_report_stats(state, manager, last, stats_timeout)?;
        }
    }

    /// Fuzz for n iterations
    /// Returns the index of the last fuzzed corpus item
    fn fuzz_loop_for(
        &mut self,
        state: &mut S,
        executor: &mut E,
        manager: &mut EM,
        scheduler: &CS,
        iters: u64,
    ) -> Result<usize, Error> {
        if iters == 0 {
            return Err(Error::IllegalArgument(
                "Cannot fuzz for 0 iterations!".to_string(),
            ));
        }

        let mut ret = 0;
        let mut last = current_time();
        let stats_timeout = STATS_TIMEOUT_DEFAULT;

        for _ in 0..iters {
            ret = self.fuzz_one(state, executor, manager, scheduler)?;
            last = Self::maybe_report_stats(state, manager, last, stats_timeout)?;
        }
        Ok(ret)
    }

    /// Given the last time, if stats_timeout seconds passed, send off an info/stats/heartbeat message to the broker.
    /// Returns the new `last` time (so the old one, unless `stats_timeout` time has passed and stats have been sent)
    /// Will return an Error, if the stats could not be sent.
    fn maybe_report_stats(
        state: &mut S,
        manager: &mut EM,
        last: Duration,
        stats_timeout: Duration,
    ) -> Result<Duration, Error>;
}

/// Your default fuzzer instance, for everyday use.
#[derive(Clone, Debug)]
pub struct StdFuzzer<CS, ST, E, EM, I, OT, S>
where
    CS: CorpusScheduler<I, S>,
    ST: StagesTuple<CS, E, EM, I, S>,
    E: Executor<I>,
    EM: EventManager<I, S>,
    I: Input,
{
    stages: ST,
    phantom: PhantomData<(CS, E, EM, I, OT, S)>,
}

impl<CS, ST, E, EM, I, OT, S> HasStages<CS, E, EM, I, S, ST> for StdFuzzer<CS, ST, E, EM, I, OT, S>
where
    CS: CorpusScheduler<I, S>,
    ST: StagesTuple<CS, E, EM, I, S>,
    E: Executor<I>,
    EM: EventManager<I, S>,
    I: Input,
{
    fn stages(&self) -> &ST {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut ST {
        &mut self.stages
    }
}

/*
impl<CS, ST, E, EM, I, OT, S> HasCorpusScheduler<CS, I, S> for StdFuzzer<CS, ST, E, EM, I, OT, S>
where
    CS: CorpusScheduler<I, S>,
    ST: StagesTuple<CS, E, EM, I, S>,
    E: Executor<I>,
    EM: EventManager<I, S>,
    I: Input,
{
    fn scheduler(&self) -> &CS {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut CS {
        &mut self.scheduler
    }
}
*/

impl<CS, ST, E, EM, I, OT, S> Fuzzer<E, EM, S, CS> for StdFuzzer<CS, ST, E, EM, I, OT, S>
where
    CS: CorpusScheduler<I, S>,
    S: HasExecutions,
    ST: StagesTuple<CS, E, EM, I, S>,
    EM: EventManager<I, S>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    I: Input,
{
    #[inline]
    fn maybe_report_stats(
        state: &mut S,
        manager: &mut EM,
        last: Duration,
        stats_timeout: Duration,
    ) -> Result<Duration, Error> {
        let cur = current_time();
        if cur - last > stats_timeout {
            //println!("Fire {:?} {:?} {:?}", cur, last, stats_timeout);
            manager.fire(
                state,
                Event::UpdateStats {
                    executions: *state.executions(),
                    time: cur,
                    phantom: PhantomData,
                },
            )?;
            Ok(cur)
        } else {
            if cur.as_millis() % 1000 == 0 {}
            Ok(last)
        }
    }

    fn fuzz_one(&mut self, state: &mut S, executor: &mut E, manager: &mut EM, scheduler: &CS) -> Result<usize, Error> {
        let idx = scheduler.next(state)?;

        self.stages_mut()
            .perform_all(state, executor, manager, scheduler, idx)?;

        manager.process(state, executor, scheduler)?;
        Ok(idx)
    }
}

impl<CS, ST, E, EM, I, OT, S> StdFuzzer<CS, ST, E, EM, I, OT, S>
where
    CS: CorpusScheduler<I, S>,
    ST: StagesTuple<CS, E, EM, I, S>,
    E: Executor<I>,
    EM: EventManager<I, S>,
    I: Input,
{
    pub fn new(stages: ST) -> Self {
        Self {
            stages,
            phantom: PhantomData,
        }
    }
}
