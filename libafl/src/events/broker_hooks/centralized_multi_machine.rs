use core::fmt::{Debug, Display};
use std::{sync::Arc, vec::Vec};

use libafl_bolts::{
    bolts_prelude::{
        Flags, LlmpBrokerInner, LlmpMsg, LlmpMsgHookResult, Tag, LLMP_FLAG_COMPRESSED,
        LLMP_FLAG_INITIALIZED,
    },
    llmp::LlmpHook,
    prelude::ShMemProvider,
    ClientId, Error,
};
use log::info;
use tokio::{
    net::ToSocketAddrs,
    runtime::Runtime,
    sync::{RwLock, RwLockWriteGuard},
};

use crate::{
    events::{multi_machine::TcpMultiMachineState, Event, _LLMP_TAG_TO_MAIN},
    inputs::Input,
};

/// The Receiving side of the multi-machine architecture
/// It is responsible for receiving messages from other neighbours.
/// Please check [`events::multi_machine`] for more information.
#[derive(Debug)]
pub struct TcpMultiMachineLlmpSenderHook<A, I>
where
    I: Input,
{
    /// the actual state of the broker hook
    shared_state: Arc<RwLock<TcpMultiMachineState<A, I>>>,
    /// the tokio runtime used to interact with other machines. Keep it outside to avoid locking it.
    rt: Arc<Runtime>,
}

/// The Receiving side of the multi-machine architecture
/// It is responsible for receiving messages from other neighbours.
/// Please check [`events::multi_machine`] for more information.
#[derive(Debug)]
pub struct TcpMultiMachineLlmpReceiverHook<A, I>
where
    I: Input,
{
    /// the actual state of the broker hook
    shared_state: Arc<RwLock<TcpMultiMachineState<A, I>>>,
    /// the tokio runtime used to interact with other machines. Keep it outside to avoid locking it.
    rt: Arc<Runtime>,
}

impl<A, I> TcpMultiMachineLlmpSenderHook<A, I>
where
    A: Clone + Display + ToSocketAddrs + Send + Sync + 'static,
    I: Input + Send + Sync + 'static,
{
    /// Should not be created alone. Use [`TcpMultiMachineBuilder`] instead.
    pub(crate) fn new(
        shared_state: Arc<RwLock<TcpMultiMachineState<A, I>>>,
        rt: Arc<Runtime>,
    ) -> Self {
        Self { shared_state, rt }
    }

    #[cfg(feature = "llmp_compression")]
    fn try_compress(
        state_lock: &mut RwLockWriteGuard<TcpMultiMachineState<A, I>>,
        event: &Event<I>,
    ) -> Result<(Flags, Vec<u8>), Error> {
        let serialized = postcard::to_allocvec(&event)?;

        match state_lock.compressor().maybe_compress(&serialized) {
            Some(comp_buf) => Ok((LLMP_FLAG_COMPRESSED, comp_buf)),
            None => Ok((Flags(0), serialized)),
        }
    }

    #[cfg(not(feature = "llmp_compression"))]
    fn try_compress(
        _state_lock: &mut RwLockWriteGuard<TcpMultiMachineState<A, I>>,
        event: &Event<I>,
    ) -> Result<(Flags, Vec<u8>), Error> {
        Ok((Flags(0), postcard::to_allocvec(&event)?))
    }
}

impl<A, I> TcpMultiMachineLlmpReceiverHook<A, I>
where
    A: Clone + Display + ToSocketAddrs + Send + Sync + 'static,
    I: Input + Send + Sync + 'static,
{
    /// Should not be created alone. Use [`TcpMultiMachineBuilder`] instead.
    pub(crate) fn new(
        shared_state: Arc<RwLock<TcpMultiMachineState<A, I>>>,
        rt: Arc<Runtime>,
    ) -> Self {
        Self { shared_state, rt }
    }

    #[cfg(feature = "llmp_compression")]
    fn try_compress(
        state_lock: &mut RwLockWriteGuard<TcpMultiMachineState<A, I>>,
        event: &Event<I>,
    ) -> Result<(Flags, Vec<u8>), Error> {
        let serialized = postcard::to_allocvec(&event)?;

        match state_lock.compressor().maybe_compress(&serialized) {
            Some(comp_buf) => Ok((LLMP_FLAG_COMPRESSED, comp_buf)),
            None => Ok((Flags(0), serialized)),
        }
    }

    #[cfg(not(feature = "llmp_compression"))]
    fn try_compress(
        _state_lock: &mut RwLockWriteGuard<TcpMultiMachineState<A, I>>,
        event: &Event<I>,
    ) -> Result<(Flags, Vec<u8>), Error> {
        Ok((Flags(0), postcard::to_allocvec(&event)?))
    }
}

impl<A, I, SP> LlmpHook<SP> for TcpMultiMachineLlmpSenderHook<A, I>
where
    A: Clone + Debug + Display + ToSocketAddrs + Send + Sync + 'static,
    SP: ShMemProvider,
    I: Input + Send + Sync + 'static,
{
    /// check for received messages, and forward them alongside the incoming message to inner.
    fn on_new_message(
        &mut self,
        _broker_inner: &mut LlmpBrokerInner<SP>,
        _client_id: ClientId,
        _msg_tag: &mut Tag,
        msg_flags: &mut Flags,
        msg: &mut [u8],
        _new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
    ) -> Result<LlmpMsgHookResult, Error> {
        let shared_state = self.shared_state.clone();

        info!("Using shared state {:?}", shared_state);

        let res: Result<(), Error> = self.rt.block_on(async move {
            let mut state_wr_lock = shared_state.write().await;

            // for event in events.as_ref() {
            //     // First, we handle the message. Since it involves network, we do it first and await on it.
            //     state_wr_lock.handle_new_message_from_node(event).await?;

            //     // add the msg to the list of old messages to send to a future child.
            //     state_wr_lock.old_events.push();
            // }

            #[cfg(not(feature = "llmp_compression"))]
            let event_bytes = msg;
            #[cfg(feature = "llmp_compression")]
            let compressed;
            #[cfg(feature = "llmp_compression")]
            let event_bytes = if *msg_flags & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
                compressed = state_wr_lock.compressor().decompress(msg)?;
                &compressed
            } else {
                &*msg
            };
            let event: Event<I> = postcard::from_bytes(event_bytes)?;

            state_wr_lock
                .send_interesting_event_to_nodes(&event)
                .await?;

            Ok(())
        });

        res?;

        // Add incoming events to the ones we should filter
        // events.extend_from_slice(&incoming_events);

        Ok(LlmpMsgHookResult::ForwardToClients)
    }
}

impl<A, I, SP> LlmpHook<SP> for TcpMultiMachineLlmpReceiverHook<A, I>
where
    A: Clone + Debug + Display + ToSocketAddrs + Send + Sync + 'static,
    SP: ShMemProvider,
    I: Input + Send + Sync + 'static,
{
    /// check for received messages, and forward them alongside the incoming message to inner.
    fn on_new_message(
        &mut self,
        _broker_inner: &mut LlmpBrokerInner<SP>,
        _client_id: ClientId,
        msg_tag: &mut Tag,
        msg_flags: &mut Flags,
        msg: &mut [u8],
        new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
    ) -> Result<LlmpMsgHookResult, Error> {
        let shared_state = self.shared_state.clone();

        info!("Using shared state {:?}", shared_state);

        let res: Result<(), Error> = self.rt.block_on(async move {
            let mut state_wr_lock = shared_state.write().await;

            // for event in events.as_ref() {
            //     // First, we handle the message. Since it involves network, we do it first and await on it.
            //     state_wr_lock.handle_new_message_from_node(event).await?;

            //     // add the msg to the list of old messages to send to a future child.
            //     state_wr_lock.old_events.push();
            // }
            let mut new_events: Vec<Event<I>> = Vec::new();
            state_wr_lock
                .receive_new_messages_from_nodes(&mut new_events)
                .await?;

            let msgs_to_send: Result<Vec<(Tag, Flags, Vec<u8>)>, Error> = new_events
                .into_iter()
                .map(|event| {
                    let (inner_flags, buf) = Self::try_compress(&mut state_wr_lock, &event)?;

                    Ok((_LLMP_TAG_TO_MAIN, inner_flags, buf))
                })
                .collect();

            new_msgs.extend(msgs_to_send?.into_iter());

            Ok(())
        });

        res?;

        // Add incoming events to the ones we should filter
        // events.extend_from_slice(&incoming_events);

        Ok(LlmpMsgHookResult::ForwardToClients)
    }
}
