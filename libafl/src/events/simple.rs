//! A very simple event manager, that just supports log outputs, but no multiprocessing
use alloc::{string::ToString, vec::Vec};
use core::marker::PhantomData;

use crate::{
    corpus::CorpusScheduler,
    events::{BrokerEventResult, Event, EventManager},
    executors::{Executor, HasObservers},
    inputs::Input,
    observers::ObserversTuple,
    stats::Stats,
    Error,
};

/// A simple, single-threaded event manager that just logs
#[derive(Clone, Debug)]
pub struct SimpleEventManager<I, S, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    /// The stats
    stats: ST,
    /// The events that happened since the last handle_in_broker
    events: Vec<Event<I>>,
    phantom: PhantomData<S>,
}

impl<I, S, ST> EventManager<I, S> for SimpleEventManager<I, S, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    fn process<CS, E, OT>(
        &mut self,
        state: &mut S,
        _executor: &mut E,
        _scheduler: &CS,
    ) -> Result<usize, Error>
    where
        CS: CorpusScheduler<I, S>,
        E: Executor<I> + HasObservers<OT>,
        OT: ObserversTuple,
    {
        let count = self.events.len();
        while !self.events.is_empty() {
            let event = self.events.pop().unwrap();
            self.handle_in_client(state, event)?;
        }
        Ok(count)
    }

    fn fire(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        match Self::handle_in_broker(&mut self.stats, &event)? {
            BrokerEventResult::Forward => self.events.push(event),
            BrokerEventResult::Handled => (),
        };
        Ok(())
    }
}

impl<I, S, ST> SimpleEventManager<I, S, ST>
where
    I: Input,
    ST: Stats, //TODO CE: CustomEvent,
{
    pub fn new(stats: ST) -> Self {
        Self {
            stats,
            events: vec![],
            phantom: PhantomData,
        }
    }

    // Handle arriving events in the broker
    #[allow(clippy::unnecessary_wraps)]
    fn handle_in_broker(stats: &mut ST, event: &Event<I>) -> Result<BrokerEventResult, Error> {
        match event {
            Event::NewTestcase {
                input: _,
                client_config: _,
                corpus_size,
                observers_buf: _,
                time,
                executions,
            } => {
                stats.client_stats_mut()[0].update_corpus_size(*corpus_size as u64);
                stats.client_stats_mut()[0].update_executions(*executions as u64, *time);
                stats.display(event.name().to_string());
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateStats {
                time,
                executions,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                stats.client_stats_mut()[0].update_executions(*executions as u64, *time);
                stats.display(event.name().to_string());
                Ok(BrokerEventResult::Handled)
            }
            Event::Objective { objective_size } => {
                stats.client_stats_mut()[0].update_objective_size(*objective_size as u64);
                stats.display(event.name().to_string());
                Ok(BrokerEventResult::Handled)
            }
            Event::Log {
                severity_level,
                message,
                phantom: _,
            } => {
                let (_, _) = (message, severity_level);
                #[cfg(feature = "std")]
                println!("[LOG {}]: {}", severity_level, message);
                Ok(BrokerEventResult::Handled)
            } //_ => Ok(BrokerEventResult::Forward),
        }
    }

    // Handle arriving events in the client
    #[allow(clippy::needless_pass_by_value, clippy::unused_self)]
    fn handle_in_client(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        Err(Error::Unknown(format!(
            "Received illegal message that message should not have arrived: {:?}.",
            event
        )))
    }
}
