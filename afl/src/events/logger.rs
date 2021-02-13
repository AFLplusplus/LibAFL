use alloc::{string::ToString, vec::Vec};

#[cfg(feature = "std")]
#[cfg(unix)]
use crate::{
    corpus::Corpus,
    events::{BrokerEventResult, Event, EventManager},
    feedbacks::FeedbacksTuple,
    inputs::Input,
    state::State,
    stats::Stats,
    utils::Rand,
    AflError,
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
    fn process<C, FT, R>(&mut self, state: &mut State<C, FT, I, R>) -> Result<usize, AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        let count = self.events.len();
        while self.events.len() > 0 {
            let event = self.events.pop().unwrap();
            self.handle_in_client(state, 0, event)?;
        }
        Ok(count)
    }

    fn fire<C, FT, R>(
        &mut self,
        _state: &mut State<C, FT, I, R>,
        event: Event<I>,
    ) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        match Self::handle_in_broker(&mut self.stats, 0, &event)? {
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
    fn handle_in_broker(
        stats: &mut ST,
        _sender_id: u32,
        event: &Event<I>,
    ) -> Result<BrokerEventResult, AflError> {
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
            Event::Crash { input: _ } => {
                panic!("LoggerEventManager cannot handle Event::Crash");
            }
            Event::Timeout { input: _ } => {
                panic!("LoggerEventManager cannot handle Event::Timeout");
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
    fn handle_in_client<C, FT, R>(
        &mut self,
        _state: &mut State<C, FT, I, R>,
        _sender_id: u32,
        event: Event<I>,
    ) -> Result<(), AflError>
    where
        C: Corpus<I, R>,
        FT: FeedbacksTuple<I>,
        R: Rand,
    {
        match event {
            _ => Err(AflError::Unknown(format!(
                "Received illegal message that message should not have arrived: {:?}.",
                event
            ))),
        }
    }
}
