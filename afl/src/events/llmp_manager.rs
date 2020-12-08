use core::marker::PhantomData;
use core::ptr;
use std::{ffi::c_void, io::Read, io::Write, net::TcpListener};

use crate::{
    corpus::Corpus, engines::State, executors::Executor, inputs::Input, utils::Rand, AflError,
};

use super::{
    llmp_translated::{LlmpBroker, LlmpClient, LlmpClientloopFn, LlmpMsgHookFn},
    Event, EventManager,
};

/// Eventmanager for multi-processed application
#[cfg(feature = "std")]
pub struct LLMPEventManager<C, E, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    R: Rand,
    //CE: CustomEvent<C, E, I, R>,
{
    // TODO...
    phantom: PhantomData<(C, E, I, R)>,
    is_broker: bool,
}

#[cfg(feature = "std")]
impl<C, E, I, R> EventManager<C, E, I, R> for LLMPEventManager<C, E, I, R>
where
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
    //CE: CustomEvent<C, E, I, R>,
{
    fn enabled(&self) -> bool {
        true
    }

    fn fire(&mut self, _event: Event<C, E, I, R>) -> Result<(), AflError> {
        //self.events.push(event);

        // TODO: Serde serialize, llmp send

        Ok(())
    }

    fn process(&mut self, _state: &mut State<I, R>, _corpus: &mut C) -> Result<usize, AflError> {
        // TODO: iterators
        /*
        let mut handled = vec![];
        for x in self.events.iter() {
            handled.push(x.handle_in_broker(state, corpus)?);
        }
        handled
            .iter()
            .zip(self.events.iter())
            .map(|(x, event)| match x {
                BrokerEventResult::Forward => event.handle_in_client(state, corpus),
                // Ignore broker-only events
                BrokerEventResult::Handled => Ok(()),
            })
            .for_each(drop);
        let count = self.events.len();
        dbg!("Handled {} events", count);
        self.events.clear();

        let num = self.events.len();
        for event in &self.events {}

        self.events.clear();
        */

        Ok(0)
    }
}

#[cfg(feature = "std")]
impl<C, E, I, R> LLMPEventManager<C, E, I, R>
where
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    R: Rand,
{
    
}
