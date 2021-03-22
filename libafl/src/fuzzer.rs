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
    fn fuzz_one(&mut self, state: &mut S, executor: &mut E, manager: &mut EM, scheduler :&CS) -> Result<usize, Error>;

    fn fuzz_loop(&mut self, state: &mut S, executor: &mut E, manager: &mut EM, scheduler :&CS) -> Result<usize, Error>;
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
    fn fuzz_one(&mut self, state: &mut S, executor: &mut E, manager: &mut EM, scheduler: &CS) -> Result<usize, Error> {
        let idx = scheduler.next(state)?;

        self.stages_mut()
            .perform_all(state, executor, manager, scheduler, idx)?;

        manager.process(state, executor, scheduler)?;
        Ok(idx)
    }

    fn fuzz_loop(&mut self, state: &mut S, executor: &mut E, manager: &mut EM, scheduler: &CS) -> Result<usize, Error> {
        let mut last = current_milliseconds();
        loop {
            self.fuzz_one(state, executor, manager, scheduler)?;
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
