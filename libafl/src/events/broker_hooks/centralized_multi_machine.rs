use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
    slice,
    sync::Arc,
    vec::Vec,
};

#[cfg(feature = "llmp_compression")]
use libafl_bolts::llmp::LLMP_FLAG_COMPRESSED;
use libafl_bolts::{
    llmp::{Flags, LlmpBrokerInner, LlmpHook, LlmpMsgHookResult, Tag, LLMP_FLAG_FROM_MM},
    ownedref::OwnedRef,
    shmem::ShMemProvider,
    ClientId, Error,
};
use tokio::{
    net::ToSocketAddrs,
    runtime::Runtime,
    sync::{RwLock, RwLockWriteGuard},
    task::JoinHandle,
};

use crate::{
    events::{
        centralized::_LLMP_TAG_TO_MAIN,
        multi_machine::{MultiMachineMsg, TcpMultiMachineState},
        Event,
    },
    inputs::Input,
};

/// Makes a raw pointer send + sync.
/// Extremely unsafe to use in general, only use this if you know what you're doing.
#[derive(Debug, Clone, Copy)]
pub struct NullLock<T> {
    value: T,
}

unsafe impl<T> Send for NullLock<T> {}
unsafe impl<T> Sync for NullLock<T> {}

impl<T> NullLock<T> {
    /// Instantiate a [`NullLock`]
    ///
    /// # Safety
    ///
    /// The null lock makes anything Send + Sync, which is usually very dangerous.
    pub unsafe fn new(value: T) -> Self {
        Self { value }
    }

    /// Get a reference to value
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Get a mutable reference to value
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Get back the value
    pub fn into_innter(self) -> T {
        self.value
    }
}

/// The Receiving side of the multi-machine architecture
/// It is responsible for receiving messages from other neighbours.
/// Please check [`crate::events::multi_machine`] for more information.
#[derive(Debug)]
pub struct TcpMultiMachineLlmpSenderHook<A, I>
where
    I: Input,
{
    /// the actual state of the broker hook
    shared_state: Arc<RwLock<TcpMultiMachineState<A>>>,
    /// the tokio runtime used to interact with other machines. Keep it outside to avoid locking it.
    rt: Arc<Runtime>,
    phantom: PhantomData<I>,
}

/// The Receiving side of the multi-machine architecture
/// It is responsible for receiving messages from other neighbours.
/// Please check [`crate::events::multi_machine`] for more information.
#[derive(Debug)]
pub struct TcpMultiMachineLlmpReceiverHook<A, I>
where
    I: Input,
{
    /// the actual state of the broker hook
    shared_state: Arc<RwLock<TcpMultiMachineState<A>>>,
    /// the tokio runtime used to interact with other machines. Keep it outside to avoid locking it.
    rt: Arc<Runtime>,
    phantom: PhantomData<I>,
}

impl<A, I> TcpMultiMachineLlmpSenderHook<A, I>
where
    A: Clone + Display + ToSocketAddrs + Send + Sync + 'static,
    I: Input + Send + Sync + 'static,
{
    /// Should not be created alone. Use [`TcpMultiMachineHooksBuilder`] instead.
    pub(crate) fn new(
        shared_state: Arc<RwLock<TcpMultiMachineState<A>>>,
        rt: Arc<Runtime>,
    ) -> Self {
        Self {
            shared_state,
            rt,
            phantom: PhantomData,
        }
    }
}

impl<A, I> TcpMultiMachineLlmpReceiverHook<A, I>
where
    A: Clone + Display + ToSocketAddrs + Send + Sync + 'static,
    I: Input + Send + Sync + 'static,
{
    /// Should not be created alone. Use [`TcpMultiMachineHooksBuilder`] instead.
    ///
    /// # Safety
    /// For [`Self::on_new_message`], this struct assumes that the `msg` parameter
    /// (or rather, the memory it points to), lives sufficiently long
    /// for an async background task to process it.
    pub(crate) unsafe fn new(
        shared_state: Arc<RwLock<TcpMultiMachineState<A>>>,
        rt: Arc<Runtime>,
    ) -> Self {
        Self {
            shared_state,
            rt,
            phantom: PhantomData,
        }
    }

    #[cfg(feature = "llmp_compression")]
    fn try_compress(
        state_lock: &mut RwLockWriteGuard<TcpMultiMachineState<A>>,
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
        _state_lock: &mut RwLockWriteGuard<TcpMultiMachineState<A>>,
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
        _msg_flags: &mut Flags,
        msg: &mut [u8],
        _new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
    ) -> Result<LlmpMsgHookResult, Error> {
        let shared_state = self.shared_state.clone();

        // # Safety
        // Here, we suppose msg will *never* be written again and will always be available.
        // Thus, it is safe to handle this in a separate thread.
        let msg_lock = unsafe { NullLock::new((msg.as_ptr(), msg.len())) };
        // let flags = msg_flags.clone();

        let _handle: JoinHandle<Result<(), Error>> = self.rt.spawn(async move {
            let mut state_wr_lock = shared_state.write().await;
            let (msg_ptr, msg_len) = msg_lock.into_innter();
            let msg: &[u8] = unsafe { slice::from_raw_parts(msg_ptr, msg_len) }; // most likely crash here

            // #[cfg(not(feature = "llmp_compression"))]
            // let event_bytes = msg;
            // #[cfg(feature = "llmp_compression")]
            // let compressed;
            // #[cfg(feature = "llmp_compression")]
            // let event_bytes = if flags & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
            //     compressed = state_wr_lock.compressor().decompress(msg)?;
            //     &compressed
            // } else {
            //     &*msg
            // };
            // let event: Event<I> = postcard::from_bytes(event_bytes)?;

            let mm_msg: MultiMachineMsg<I> = MultiMachineMsg::llmp_msg(OwnedRef::Ref(msg));

            // TODO: do not copy here
            state_wr_lock.add_past_msg(msg);

            log::debug!("Sending msg...");

            state_wr_lock
                .send_interesting_event_to_nodes(&mm_msg)
                .await?;

            log::debug!("msg sent.");

            Ok(())
        });

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
        _msg_tag: &mut Tag,
        _msg_flags: &mut Flags,
        _msg: &mut [u8],
        new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
    ) -> Result<LlmpMsgHookResult, Error> {
        let shared_state = self.shared_state.clone();

        let res: Result<(), Error> = self.rt.block_on(async move {
            let mut state_wr_lock = shared_state.write().await;

            let mut incoming_msgs: Vec<MultiMachineMsg<I>> = Vec::new();
            state_wr_lock
                .receive_new_messages_from_nodes(&mut incoming_msgs)
                .await?;

            log::debug!("received {} new incoming msg(s)", incoming_msgs.len());

            let msgs_to_forward: Result<Vec<(Tag, Flags, Vec<u8>)>, Error> = incoming_msgs
                .into_iter()
                .map(|mm_msg| match mm_msg {
                    MultiMachineMsg::LlmpMsg(msg) => {
                        let msg = msg.into_owned().unwrap().into_vec();
                        #[cfg(feature = "llmp_compression")]
                        match state_wr_lock.compressor().maybe_compress(msg.as_ref()) {
                            Some(comp_buf) => Ok((
                                _LLMP_TAG_TO_MAIN,
                                LLMP_FLAG_COMPRESSED | LLMP_FLAG_FROM_MM,
                                comp_buf,
                            )),
                            None => Ok((_LLMP_TAG_TO_MAIN, LLMP_FLAG_FROM_MM, msg)),
                        }
                        #[cfg(not(feature = "llmp_compression"))]
                        Ok((_LLMP_TAG_TO_MAIN, LLMP_FLAG_FROM_MM, msg))
                    }
                    MultiMachineMsg::Event(evt) => {
                        let evt = evt.into_owned().unwrap();
                        let (inner_flags, buf) =
                            Self::try_compress(&mut state_wr_lock, evt.as_ref())?;

                        Ok((_LLMP_TAG_TO_MAIN, inner_flags | LLMP_FLAG_FROM_MM, buf))
                    }
                })
                .collect();

            new_msgs.extend(msgs_to_forward?);

            Ok(())
        });

        res?;

        // Add incoming events to the ones we should filter
        // events.extend_from_slice(&incoming_events);

        Ok(LlmpMsgHookResult::ForwardToClients)
    }
}
