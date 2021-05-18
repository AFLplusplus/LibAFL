//! A very simple event manager, that just supports log outputs, but no multiprocessing
use alloc::{string::ToString, vec::Vec};

use crate::{
    events::{BrokerEventResult, Event, EventFirer, EventManager, EventProcessor, EventRestarter},
    inputs::Input,
    stats::Stats,
    Error,
};

/// A simple, single-threaded event manager that just logs
#[derive(Clone, Debug)]
pub struct SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    /// The stats
    stats: ST,
    /// The events that happened since the last handle_in_broker
    events: Vec<Event<I>>,
}

impl<I, S, ST> EventFirer<I, S> for SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    fn fire(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        match Self::handle_in_broker(&mut self.stats, &event)? {
            BrokerEventResult::Forward => self.events.push(event),
            BrokerEventResult::Handled => (),
        };
        Ok(())
    }
}

impl<I, S, ST> EventRestarter<S> for SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
}

impl<E, I, S, ST, Z> EventProcessor<E, S, Z> for SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    fn process(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _executor: &mut E,
    ) -> Result<usize, Error> {
        let count = self.events.len();
        while !self.events.is_empty() {
            let event = self.events.pop().unwrap();
            self.handle_in_client(state, event)?;
        }
        Ok(count)
    }
}

impl<E, I, S, ST, Z> EventManager<E, I, S, Z> for SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
}

impl<I, ST> SimpleEventManager<I, ST>
where
    I: Input,
    ST: Stats, //TODO CE: CustomEvent,
{
    /// Creates a new [`SimpleEventManager`].
    pub fn new(stats: ST) -> Self {
        Self {
            stats,
            events: vec![],
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
                stats
                    .client_stats_mut_for(0)
                    .update_corpus_size(*corpus_size as u64);
                stats
                    .client_stats_mut_for(0)
                    .update_executions(*executions as u64, *time);
                stats.display(event.name().to_string());
                Ok(BrokerEventResult::Handled)
            }
            Event::UpdateStats {
                time,
                executions,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                stats
                    .client_stats_mut_for(0)
                    .update_executions(*executions as u64, *time);
                stats.display(event.name().to_string());
                Ok(BrokerEventResult::Handled)
            }
            #[cfg(feature = "introspection")]
            Event::UpdatePerfStats {
                time,
                executions,
                introspection_stats,
                phantom: _,
            } => {
                // TODO: The stats buffer should be added on client add.
                stats.client_stats_mut()[0].update_executions(*executions as u64, *time);
                stats.client_stats_mut()[0].update_introspection_stats(**introspection_stats);
                stats.display(event.name().to_string());
                Ok(BrokerEventResult::Handled)
            }
            Event::FeedbackStats { feedbacks } => {
                if stats.client_stats_mut().len() > 0 {
                    stats.client_stats_mut()[0].update_feedbacks(*feedbacks as u64);
                }
                Ok(BrokerEventResult::Handled)
            },
            Event::Objective { objective_size } => {
                stats
                    .client_stats_mut_for(0)
                    .update_objective_size(*objective_size as u64);
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
    fn handle_in_client<S>(&mut self, _state: &mut S, event: Event<I>) -> Result<(), Error> {
        Err(Error::Unknown(format!(
            "Received illegal message that message should not have arrived: {:?}.",
            event
        )))
    }
}
