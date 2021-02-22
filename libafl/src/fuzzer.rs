use crate::{
    corpus::CorpusScheduler,
    events::{Event, EventManager},
    executors::{Executor, HasObservers},
    inputs::Input,
    observers::ObserversTuple,
    stages::StagesTuple,
    state::HasExecutions,
    utils::{current_milliseconds, current_time},
    Error,
};
use core::marker::PhantomData;

/// Holds a set of stages
pub trait HasStages<ST, E, EM, S>: Sized
where
    ST: StagesTuple<E, EM, Self, S>,
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
pub trait Fuzzer<E, EM, S> {
    fn fuzz_one(&self, state: &mut S, executor: &mut E, manager: &mut EM) -> Result<usize, Error>;

    fn fuzz_loop(&self, state: &mut S, executor: &mut E, manager: &mut EM) -> Result<usize, Error>;
}

/// Your default fuzzer instance, for everyday use.
#[derive(Clone, Debug)]
pub struct StdFuzzer<CS, ST, E, EM, I, OT, S>
where
    CS: CorpusScheduler<I, S>,
    ST: StagesTuple<E, EM, Self, S>,
    I: Input,
{
    scheduler: CS,
    stages: ST,
    phantom: PhantomData<(E, EM, I, OT, S)>,
}

impl<CS, ST, E, EM, I, OT, S> HasStages<ST, E, EM, S> for StdFuzzer<CS, ST, E, EM, I, OT, S>
where
    CS: CorpusScheduler<I, S>,
    ST: StagesTuple<E, EM, Self, S>,
    I: Input,
{
    fn stages(&self) -> &ST {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut ST {
        &mut self.stages
    }
}

impl<CS, ST, E, EM, I, OT, S> HasCorpusScheduler<CS, I, S> for StdFuzzer<CS, ST, E, EM, I, OT, S>
where
    CS: CorpusScheduler<I, S>,
    ST: StagesTuple<E, EM, Self, S>,
    I: Input,
{
    fn scheduler(&self) -> &CS {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut CS {
        &mut self.scheduler
    }
}

impl<CS, ST, E, EM, I, OT, S> Fuzzer<E, EM, S> for StdFuzzer<CS, ST, E, EM, I, OT, S>
where
    CS: CorpusScheduler<I, S>,
    S: HasExecutions,
    ST: StagesTuple<E, EM, Self, S>,
    EM: EventManager<I, S>,
    E: Executor<I> + HasObservers<OT>,
    OT: ObserversTuple,
    I: Input,
{
    fn fuzz_one(&self, state: &mut S, executor: &mut E, manager: &mut EM) -> Result<usize, Error> {
        let idx = self.scheduler().next(state)?;

        self.stages()
            .perform_all(self, state, executor, manager, idx)?;

        manager.process(state, executor)?;
        Ok(idx)
    }

    fn fuzz_loop(&self, state: &mut S, executor: &mut E, manager: &mut EM) -> Result<usize, Error> {
        let mut last = current_milliseconds();
        loop {
            self.fuzz_one(state, executor, manager)?;
            let cur = current_milliseconds();
            if cur - last > 60 * 100 {
                last = cur;
                manager.fire(
                    state,
                    Event::UpdateStats {
                        executions: *state.executions(),
                        time: current_time(),
                        phantom: PhantomData,
                    },
                )?
            }
        }
    }
}

impl<CS, ST, E, EM, I, OT, S> StdFuzzer<CS, ST, E, EM, I, OT, S>
where
    CS: CorpusScheduler<I, S>,
    ST: StagesTuple<E, EM, Self, S>,
    I: Input,
{
    pub fn new(scheduler: CS, stages: ST) -> Self {
        Self {
            scheduler: scheduler,
            stages: stages,
            phantom: PhantomData,
        }
    }
}
