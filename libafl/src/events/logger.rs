use alloc::{string::ToString, vec::Vec};

#[cfg(feature = "std")]
#[cfg(unix)]
use crate::{
    corpus::Corpus,
    events::{BrokerEventResult, Event, EventManager},
    executors::{Executor, HasObservers},
    feedbacks::FeedbacksTuple,
    inputs::Input,
    observers::ObserversTuple,
    state::State,
    stats::Stats,
    utils::Rand,
    Error,
};

/// A simple, single-threaded event manager that just logs
#[derive(Clone, Debug)]
pub struct LoggerEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    /// The stats
    stats: ST,
    /// The events that happened since the last handle_in_broker
    events: Vec<Event<I>>,
}

impl<I, ST> EventManager<I> for LoggerEventManager<I, ST>
where
    I: Input,
    ST: Stats, //CE: CustomEvent<I, OT>,
{
    fn process<C, E, FT, OC, OFT, OT, R>(
        &mut self,
        state: &mut State<C, FT, I, OC, OFT, R>,
        _executor: &mut E,
    ) -> Result<usize, Error>
    where
        C: Corpus<I, R>,
        E: Executor<I> + HasObservers<OT>,
        FT: FeedbacksTuple<I>,
        R: Rand,
        OC: Corpus<I, R>,
        OFT: FeedbacksTuple<I>,
        OT: ObserversTuple,
    {
        let count = self.events.len();
        while self.events.len() > 0 {
            let event = self.events.pop().unwrap();
            self.handle_in_client(state, event)?;
        }
        Ok(count)
    }

    fn fire<C, FT, OC, OFT, R>(
        &mut self,
        _state: &mut State<C, FT, I, OC, OFT, R>,
        event: Event<I>,
    ) -> Result<(), Error>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
        OC: Corpus<I, R>,
        OFT: FeedbacksTuple<I>,
    {
        match Self::handle_in_broker(&mut self.stats, &event)? {
            BrokerEventResult::Forward => self.events.push(event),
            BrokerEventResult::Handled => (),
        };
        Ok(())
    }
}

impl<I, ST> LoggerEventManager<I, ST>
where
    I: Input,
    ST: Stats, //TODO CE: CustomEvent,
{
    pub fn new(stats: ST) -> Self {
        Self {
            stats: stats,
            events: vec![],
        }
    }

    // Handle arriving events in the broker
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
    fn handle_in_client<C, FT, OC, OFT, R>(
        &mut self,
        _state: &mut State<C, FT, I, OC, OFT, R>,
        event: Event<I>,
    ) -> Result<(), Error>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
        OC: Corpus<I, R>,
        OFT: FeedbacksTuple<I>,
    {
        match event {
            _ => Err(Error::Unknown(format!(
                "Received illegal message that message should not have arrived: {:?}.",
                event
            ))),
        }
    }
}
