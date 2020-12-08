use core::marker::PhantomData;
use std::{ffi::c_void, io::Read, io::Write, net::TcpListener};

use crate::{
    corpus::Corpus, engines::State, executors::Executor, inputs::Input, utils::Rand, AflError,
};

use super::{
    llmp_translated::{LlmpBroker, LlmpClient, LlmpMsgHookFn},
    Event, EventManager,
};

/*
pub unsafe fn llmp_tcp_server_clientloop(client: &mut LlmpClient, _data: *mut c_void) -> ! {
    // Later in the execution, after the initial map filled up,
    // the current broacast map will will point to a different map.
    // However, the original map is (as of now) never freed, new clients will start
    // to read from the initial map id.
    let initial_broadcasts_map_str = client
        .as_ref()
        .unwrap()
        .current_broadcast_map
        .as_ref()
        .unwrap()
        .shm_str;

    let listener = TcpListener::bind("0.0.0.0:3333").unwrap();
    // accept connections and process them, spawning a new thread for each one
    println!("Server listening on port 3333");
    loop {
        let (mut stream, addr) = match listener.accept() {
            Ok(res) => res,
            Err(e) => {
                dbg!("Ignoring failed accept", e);
                continue;
            }
        };
        dbg!("New connection", addr, stream.peer_addr().unwrap());
        match stream.write(&initial_broadcasts_map_str as &[u8]) {
            Ok(_) => {} // fire & forget
            Err(e) => {
                dbg!("Could not send to shmap to client", e);
                continue;
            }
        };
        let mut new_client_map_str: [u8; 20] = Default::default();
        let map_str_len = match stream.read(&mut new_client_map_str) {
            Ok(res) => res,
            Err(e) => {
                dbg!("Ignoring failed read from client", e);
                continue;
            }
        };
        if map_str_len < 20 {
            dbg!("Didn't receive a complete shmap id str from client. Ignoring.");
            continue;
        }
    }
}
*/

/// Eventmanager for multi-processed application
#[cfg(feature = "std")]
pub struct LLMPEventManager<S, C, E, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    R: Rand,
    //CE: CustomEvent<S, C, E, I, R>,
{
    // TODO...
    phantom: PhantomData<(S, C, E, I, R)>,
    is_broker: bool,
}

#[cfg(feature = "std")]
impl<S, C, E, I, R> EventManager<S, C, E, I, R> for LLMPEventManager<S, C, E, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    E: Executor<I>,
    I: Input,
    R: Rand,
    //CE: CustomEvent<S, C, E, I, R>,
{
    fn enabled(&self) -> bool {
        true
    }

    fn fire(&mut self, _event: Event<S, C, E, I, R>) -> Result<(), AflError> {
        //self.events.push(event);

        // TODO: Serde serialize, llmp send

        Ok(())
    }

    fn process(&mut self, _state: &mut S, _corpus: &mut C) -> Result<usize, AflError> {
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

/*
#[cfg(feature = "std")]
impl<S, C, E, I, R> LLMPEventManager<S, C, E, I, R>
where
    S: State<C, E, I, R>,
    C: Corpus<I, R>,
    I: Input,
    E: Executor<I>,
    R: Rand,
{
    /// Forks n processes, calls broker handler and client handlers, never returns.
    pub fn spawn(
        process_count: usize,
        broker_message_hook: LlmpMsgHookFn,
        clientloops: LlmpClientloopFn,
    ) -> ! {
    }
}*/
