use core::fmt::Display;
use std::{
    collections::HashMap,
    marker::PhantomData,
    mem::MaybeUninit,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock,
    },
    thread::sleep,
    time::Duration,
    vec::Vec,
};

use bitcode::{Decode, Encode};
use enumflags2::{bitflags, BitFlags};
use libafl_bolts::{
    bolts_prelude::{Flags, LlmpMsgHookResult, Tag},
    current_time,
    llmp::LlmpHook,
    shmem::ShMemProvider,
    ClientId, Error,
};
use log::info;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    runtime::Runtime,
    sync::RwLock,
    task::JoinHandle,
};
use typed_builder::TypedBuilder;

use crate::{
    events::{
        hooks::EventManagerHook,
        multi_machine::{NodeDescriptor, TcpMultiMachineState},
        Event,
    },
    inputs::Input,
    state::State,
};

#[derive(Debug)]
pub struct TcpMultiMachineEventManagerHook<I>
where
    I: Input,
{
    shared_state: Arc<RwLock<TcpMultiMachineState<I>>>, // the actual state of the broker hook
    rt: Arc<Runtime>, // the tokio runtime used to interact with other machines. Keep it outside to avoid locking it.
}

impl<I> TcpMultiMachineEventManagerHook<I>
where
    I: Input,
{
    pub(crate) fn new(
        shared_state: Arc<RwLock<TcpMultiMachineState<I>>>,
        rt: Arc<Runtime>,
    ) -> Self {
        Self { shared_state, rt }
    }
}

impl<S> EventManagerHook<S> for TcpMultiMachineEventManagerHook<S::Input>
where
    S: State,
{
    fn pre_exec(
        &mut self,
        _state: &mut S,
        _client_id: ClientId,
        events: &mut Vec<Event<S::Input>>,
    ) -> Result<bool, Error> {
        // Here, we get all the events from the other clients. we don't want to actually send them directly to
        // other nodes now. We will though receive other nodes' messages and make them go through the centralized
        // filter.
        let shared_state = self.shared_state.clone();
        let incoming_events: Vec<Event<S::Input>> = self.rt.block_on(async move {
            let mut state_wr_lock = shared_state.write().await;

            // for event in events.as_ref() {
            //     // First, we handle the message. Since it involves network, we do it first and await on it.
            //     state_wr_lock.handle_new_message_from_node(event).await?;

            //     // add the msg to the list of old messages to send to a future child.
            //     state_wr_lock.old_events.push();
            // }

            let mut incoming_events = Vec::new();
            state_wr_lock.handle_new_messages_from_nodes(&mut incoming_events)?;

            // TODO: remove once debug is over
            {
                log::debug!("New incoming events: {:?}", incoming_events);
            }

            Ok(incoming_events)
        })?;

        // Add incoming events to the ones we should filter
        events.extend_from_slice(&incoming_events);

        Ok(true)
    }
}
