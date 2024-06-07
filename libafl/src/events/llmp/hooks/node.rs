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
#[cfg(feature = "llmp_compression")]
use libafl_bolts::bolts_prelude::GzipCompressor;
#[cfg(feature = "llmp_compression")]
use libafl_bolts::bolts_prelude::LLMP_FLAG_COMPRESSED;
use libafl_bolts::{
    bolts_prelude::{Flags, LlmpBrokerState, LlmpMsgHookResult, Tag},
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

use crate::{events::Event, inputs::Input};

const LISTEN_PORT_BASE: u16 = 50000;

#[bitflags(default = ForwardToParent | ForwardToChildren | ChildrenToParent | ParentToChildren)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum NodePolicy {
    // From current node to neighbours
    SendToParent,
    SendToChildren,

    // From neighbours to neighbours
    ForwardFromChildrenToParent, // Incoming messages from children are forwarded to the parent, if any.
    ForwardFromParentToChildren, // Incoming messages from parent are forwarded to children and children to come in the future.
}

/// A node in the multi-machine model event manager.
///
/// Currently, a node can have 0 to 1 parent and multiple children.
///
/// This pattern allows for children-to-parent testcase handling.
/// Once a machine will detect a testcase that is deemed interesting, it will be forwarded to the
/// parent.
#[derive(Debug)]
pub struct TcpNodeLlmpHook<I> {
    shared_state: Arc<RwLock<TcpNodeEventLlmpSharedState>>, // the actual state of the broker hook
    rt: Runtime, // the tokio runtime used to interact with other machines. Keep it outside to avoid locking it.
    phantom: PhantomData<I>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u64);

impl NodeId {
    pub fn new() -> Self {
        static CTR: OnceLock<AtomicU64> = OnceLock::new();
        let ctr = CTR.get_or_init(|| AtomicU64::new(0));
        NodeId(ctr.fetch_add(1, Ordering::Relaxed))
    }
}

/// The state of the hook shared between the background threads and the main thread.
#[derive(Debug)]
pub struct TcpNodeEventLlmpSharedState {
    parent: Option<TcpStream>, // the parent to which the testcases should be forwarded when deemed interesting
    children: HashMap<NodeId, TcpStream>, // The children who connected during the fuzzing session.
    old_events: Vec<Vec<u8>>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
    flags: BitFlags<NodePolicy>,
}

/// The tree descriptor for the
#[derive(Debug, TypedBuilder)]
pub struct NodeDescriptor<A> {
    pub parent_addr: Option<A>, // The parent addr, if there is one.
    #[builder(default = 0)]
    pub max_nb_children: u16, // the max amount of children.
    #[builder(default = Duration::from_secs(60))]
    pub timeout: Duration, // The timeout for connecting to parent
    #[builder(default_code = "BitFlags::default()")]
    pub flags: BitFlags<NodePolicy>, // The policy for shared messages between nodes.
}

impl<I> TcpNodeLlmpHook<I> {
    /// Build a new [`TcpNodeLlmpHook`] from a [`NodeDescriptor`]
    pub fn new<A: ToSocketAddrs + Display>(
        node_descriptor: &NodeDescriptor<A>,
    ) -> Result<Self, Error> {
        // Tokio runtime, useful to welcome new children.
        let rt =
            Runtime::new().or_else(|_| Err(Error::unknown("Tokio runtime spawning failed")))?;

        // Try to connect to the parent if we should
        let parent: Option<TcpStream> = rt.block_on(async {
            if let Some(parent_addr) = &node_descriptor.parent_addr {
                let timeout = current_time() + node_descriptor.timeout;

                loop {
                    log::info!("Trying to connect to parent @ {}..", parent_addr);
                    match TcpStream::connect(parent_addr).await {
                        Ok(stream) => {
                            log::info!("Connected to parent @ {}", parent_addr);

                            break Ok(Some(stream));
                        }
                        Err(e) => {
                            if current_time() > timeout {
                                return Err(Error::os_error(e, "Unable to connect to parent"));
                            }
                        }
                    }

                    sleep(Duration::from_secs(1));
                }
            } else {
                Ok(None)
            }
        })?;

        // Create the state of the hook. This will be shared with the background server, so we wrap
        // it with concurrent-safe objects
        let state = Arc::new(RwLock::new(TcpNodeEventLlmpSharedState {
            parent,
            children: HashMap::default(),
            old_events: Vec::new(),
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(),
            flags: node_descriptor.flags,
        }));

        // Now, setup the background tasks for the children to connect to
        for i in 0..node_descriptor.max_nb_children {
            let bg_state = state.clone();
            let _: JoinHandle<Result<(), std::io::Error>> = rt.spawn(async move {
                let port = LISTEN_PORT_BASE + i;
                let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
                let state = bg_state;

                loop {
                    let (stream, _) = listener.accept().await?;
                    let mut state_guard = state.write().await;

                    state_guard.children.insert(NodeId::new(), stream);
                }
            });
        }

        Ok(Self {
            shared_state: state,
            rt,
            phantom: PhantomData,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TcpNodeMsg {
    // id: ClientId,
    msg: Vec<u8>,
}

impl TcpNodeEventLlmpSharedState {
    /// Read a [`TcpNodeMsg`] from a stream.
    /// Expects a message written by [`TcpNodeEventLlmpSharedState::write_msg`].
    async fn read_msg(&mut self, stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
        // 1. Read msg size
        let mut node_msg_len: [u8; 4] = [0; 4];
        stream.read_exact(&mut node_msg_len).await?;
        let node_msg_len = u32::from_le_bytes(node_msg_len) as usize;

        // 2. Read msg
        // do not store msg on the stack to avoid overflow issues
        let mut node_msg: Vec<u8> = Vec::with_capacity(node_msg_len);
        unsafe {
            node_msg.set_len(node_msg_len);
        }
        stream.read_exact(node_msg.as_mut_slice()).await?;

        Ok(node_msg)
    }

    /// Write a [`TcpNodeMsg`] to a stream.
    /// Can be read back using [`TcpNodeEventLlmpSharedState::read_msg`].
    async fn write_msg(&mut self, stream: &mut TcpStream, msg: &Vec<u8>) -> Result<(), Error> {
        let msg_len = u32::to_le_bytes(msg.len() as u32);

        // 1. Write msg size
        stream.write(&msg_len).await?;

        // 2. Write msg
        stream.write(msg).await?;

        Ok(())
    }

    /// The message was received because the main sent something to the broker
    async fn handle_new_message_from_node(
        &mut self,
        msg: &Vec<u8>,
    ) -> Result<Vec<TcpNodeMsg>, Error> {
        if let Some(parent) = &mut self.parent {
            if self.flags.contains(NodePolicy::ForwardToParent) {
                match self.write_msg(parent, msg).await {
                    Err(_) => {
                        // most likely the parent disconnected. drop the connection
                        info!(
                            "The parent disconnected. We won't try to communicate with it again."
                        );
                        self.parent.take();
                    }
                    Ok(_) => {} // write was successful, continue
                }
            }
        }

        if self.flags.contains(NodePolicy::ForwardToChildren) {
            let mut ids_to_remove: Vec<NodeId> = Vec::new();
            for (child_id, child_stream) in &mut self.children {
                match self.write_msg(child_stream, msg) {
                    Err(_) => {
                        // most likely the child disconnected. drop the connection later on and continue.
                        info!("The child disconnected. We won't try to communicate with it again.");
                        to_remove.push(child_id.clone());
                    }
                    Ok(_) => {} // write was successful, continue
                }
            }

            // Garbage collect children
            for id_to_remove in &ids_to_remove {
                self.children.remove(id_to_remove);
            }
        }

        Ok(())
    }
}

impl<I, SP> LlmpHook<SP> for TcpNodeLlmpHook<I>
where
    I: Input,
    SP: ShMemProvider + 'static,
{
    fn on_new_message(
        &mut self,
        _llmp_broker_state: &mut LlmpBrokerState<SP>,
        _client_id: ClientId,
        _msg_tag: &mut Tag,
        msg_flags: &mut Flags,
        msg: &mut [u8],
    ) -> Result<LlmpMsgHookResult, Error> {
        let shared_state = self.shared_state.clone();
        let _: Result<(), Error> = self.rt.block_on(async {
            let mut state_wr_lock = shared_state.write().await;

            // First, we handle the message. Since it involves network, we do it first and await on it.
            state_wr_lock.handle_new_message(msg.as_ref()).await?;

            // add the msg to the list of old messages to send to a future child.
            state_wr_lock.old_events.push(Vec::from(msg.as_ref()));

            // TODO: remove once debug is over
            {
                #[cfg(feature = "llmp_compression")]
                let compressor = &state_wr_lock.compressor;
                #[cfg(not(feature = "llmp_compression"))]
                let event_bytes = msg;
                #[cfg(feature = "llmp_compression")]
                let compressed;
                #[cfg(feature = "llmp_compression")]
                let event_bytes = if *msg_flags & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
                    compressed = compressor.decompress(msg)?;
                    &compressed
                } else {
                    &*msg
                };
                let event: Event<I> = postcard::from_bytes(event_bytes)?;

                log::debug!(
                    "[{}] New event: {:?}",
                    state_wr_lock.old_events.len(),
                    event
                );
            }

            Ok(())
        });

        // Always forward to client, we do not filter.
        Ok(LlmpMsgHookResult::ForwardToClients)
    }
}
