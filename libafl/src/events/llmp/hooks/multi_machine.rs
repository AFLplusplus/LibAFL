use std::sync::Arc;

use libafl_bolts::{
    bolts_prelude::{Flags, LlmpBrokerInner, LlmpMsgHookResult, Tag, LLMP_FLAG_COMPRESSED},
    llmp::LlmpHook,
    prelude::ShMemProvider,
    ClientId, Error,
};
use tokio::{runtime::Runtime, sync::RwLock};

use crate::{
    events::{multi_machine::TcpMultiMachineState, Event},
    inputs::Input,
};

#[derive(Clone, Debug)]
pub struct TcpMultiMachineLlmpHook<I>
where
    I: Input,
{
    shared_state: Arc<RwLock<TcpMultiMachineState<I>>>, // the actual state of the broker hook
    rt: Arc<Runtime>, // the tokio runtime used to interact with other machines. Keep it outside to avoid locking it.
}

impl<I> TcpMultiMachineLlmpHook<I>
where
    I: Input,
{
    /// Should not be created alone. Use [`TcpMultiMachineBuilder`] instead.
    pub(crate) fn new(
        shared_state: Arc<RwLock<TcpMultiMachineState<I>>>,
        rt: Arc<Runtime>,
    ) -> Self {
        Self { shared_state, rt }
    }
}

impl<SP, I> LlmpHook<SP> for TcpMultiMachineLlmpHook<I>
where
    SP: ShMemProvider,
    I: Input,
{
    /// On new message, forward every message from main to other nodes (according to policy)
    fn on_new_message(
        &mut self,
        _broker_inner: &mut LlmpBrokerInner<SP>,
        _client_id: ClientId,
        _msg_tag: &mut Tag,
        msg_flags: &mut Flags,
        msg: &mut [u8],
    ) -> Result<LlmpMsgHookResult, Error> {
        log::info!("On new message starts.");
        // Here, we can access all the messages that passed the EventManager filters.
        // Thus, the messages are initially destined to be broadcast to the other clients because they were deemed interesting.

        let shared_state = self.shared_state.clone();
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

            // TODO: remove once debug is over
            // {
            //     log::debug!("New incoming events: {:?}", incoming_events);
            // }

            Ok(())
        });

        res?;

        // Add incoming events to the ones we should filter
        // events.extend_from_slice(&incoming_events);

        Ok(LlmpMsgHookResult::ForwardToClients)
    }
}
