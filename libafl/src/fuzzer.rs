use core::{marker::PhantomData};
 
use crate::{
    corpus::{CorpusScheduler},
    events::{Event, EventManager},
    executors::{Executor},
    inputs::Input,
    stages::StagesTuple,
    utils::{current_milliseconds, current_time},
    Error
};

/// Holds a set of stages
pub trait HasStages<ST>
where
    ST: StagesTuple,
{
    fn stages(&self) -> &ST;

    fn stages_mut(&mut self) -> &mut ST;
}

/// Holds a set of stages
pub trait HasCorpusScheduler<CS>
where
    CS: CorpusScheduler,
{
    fn scheduler(&self) -> &CS;

    fn scheduler_mut(&mut self) -> &mut CS;
}

/// The main fuzzer trait.
pub trait Fuzzer<CS, ST, I>: HasCorpusScheduler<CS> + HasStages<ST>
where
    CS: CorpusScheduler,
    ST: StagesTuple<I>,
    I: Input
{
    fn fuzz_one<E, EM, S>(
        &mut self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, Error>
    where
        EM: EventManager<I>,
        E: Executor<I>,
    {
        let idx = self.scheduler().next(state)?;

        self.stages()
            .perform_all(executor, state, manager, idx)?;

        manager.process(state, executor)?;
        Ok(idx)
    }

    fn fuzz_loop<E, EM, S>(
        &mut self,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<usize, Error>
    where
        EM: EventManager<I>,
        E: Executor<I>,
    {
        let mut last = current_milliseconds();
        loop {
            self.fuzz_one(executor, state, manager)?;
            let cur = current_milliseconds();
            if cur - last > 60 * 100 {
                last = cur;
                manager.fire(
                    state,
                    Event::UpdateStats {
                        executions: state.executions(),
                        time: current_time(),
                        phantom: PhantomData,
                    },
                )?
            }
        }
    }
}

/// Your default fuzzer instance, for everyday use.
#[derive(Clone, Debug)]
pub struct StdFuzzer<CS, ST, I>
where
    CS: CorpusScheduler,
    ST: StagesTuple<I>,
    I: Input
{
    scheduler: CS,
    stages: ST,
}

impl<CS, ST, I> HasStages<ST> for StdFuzzer<CS, ST, I>
where
    CS: CorpusScheduler,
    ST: StagesTuple<I>,
    I: Input
{
    fn stages(&self) -> &ST {
        &self.stages
    }

    fn stages_mut(&mut self) -> &mut ST {
        &mut self.stages
    }
}

impl<CS, ST, I> HasCorpusScheduler<CS> for StdFuzzer<CS, ST, I>
where
    CS: CorpusScheduler,
    ST: StagesTuple<I>,
    I: Input
{
    fn scheduler(&self) -> &CS {
        &self.scheduler
    }

    fn scheduler_mut(&mut self) -> &mut CS {
        &mut self.scheduler
    }
}

impl<CS, ST, I> StdFuzzer<CS, ST, I>
where
    CS: CorpusScheduler,
    ST: StagesTuple<I>,
    I: Input
{
    pub fn new(scheduler: CS, stages: ST) -> Self {
        Self {
            scheduler: scheduler,
            stages: stages,
        }
    }
}
