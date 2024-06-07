use core::fmt::Display;
use std::{
    collections::HashMap,
    prelude::rust_2015::Vec,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock,
    },
    time::Duration,
};

use enumflags2::{bitflags, BitFlags};
use libafl_bolts::{current_time, Error};
use log::info;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    runtime::Runtime,
    sync::RwLock,
    task::JoinHandle,
    time,
};
use typed_builder::TypedBuilder;

use crate::{
    events::{
        hooks::multi_machine::TcpMultiMachineEventManagerHook,
        llmp::multi_machine::TcpMultiMachineLlmpHook, Event,
    },
    inputs::Input,
    prelude::State,
};

const LISTEN_PORT_BASE: u16 = 50000;

#[bitflags(default = ForwardToParent | ForwardToChildren | ChildrenToParent | ParentToChildren)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum NodePolicy {
    // From current node to neighbours
    SendToParent,
    SendToChildren,
    // From neighbours to neighbours
    // ForwardFromChildrenToParent, // Incoming messages from children are forwarded to the parent, if any.
    // ForwardFromParentToChildren, // Incoming messages from parent are forwarded to children and children to come in the future.
}

const DUMMY_BYTE: u8 = 0x14;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct TcpNodeMsg<I>
where
    I: Input,
{
    // id: NodeId,
    event: Event<I>,
}

impl<I> TcpNodeMsg<I>
where
    I: Input,
{
    pub fn new(event: Event<I>) -> TcpNodeMsg<I> {
        TcpNodeMsg { event }
    }
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
pub struct TcpMultiMachineState<I>
where
    I: Input,
{
    parent: Option<TcpStream>, // the parent to which the testcases should be forwarded when deemed interesting
    children: HashMap<NodeId, TcpStream>, // The children who connected during the fuzzing session.
    old_events: Vec<Event<I>>,
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

pub struct TcpMultiMachineBuilder {}

impl TcpMultiMachineBuilder {
    /// Build a new [`TcpMultiMachineEventManagerHook`] from a [`NodeDescriptor`]
    pub fn new<A: ToSocketAddrs + Display, I>(
        node_descriptor: &NodeDescriptor<A>,
    ) -> Result<
        (
            TcpMultiMachineEventManagerHook<I>,
            TcpMultiMachineLlmpHook<I>,
        ),
        Error,
    > {
        // Tokio runtime, useful to welcome new children.
        let rt = Arc::new(
            Runtime::new().or_else(|_| Err(Error::unknown("Tokio runtime spawning failed"))),
        )?;

        // Try to connect to the parent if we should
        let parent: Option<TcpStream> = rt.block_on(async {
            if let Some(parent_addr) = &node_descriptor.parent_addr {
                let timeout = current_time() + node_descriptor.timeout;

                loop {
                    info!("Trying to connect to parent @ {}..", parent_addr);
                    match TcpStream::connect(parent_addr).await {
                        Ok(stream) => {
                            info!("Connected to parent @ {}", parent_addr);

                            break Ok(Some(stream));
                        }
                        Err(e) => {
                            if current_time() > timeout {
                                return Err(Error::os_error(e, "Unable to connect to parent"));
                            }
                        }
                    }

                    time::sleep(Duration::from_secs(1)).await;
                }
            } else {
                Ok(None)
            }
        })?;

        // Create the state of the hook. This will be shared with the background server, so we wrap
        // it with concurrent-safe objects
        let state = Arc::new(RwLock::new(TcpMultiMachineState {
            parent,
            children: HashMap::default(),
            old_events: Vec::new(),
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

        Ok((
            TcpMultiMachineEventManagerHook::new(state.clone(), rt.clone()),
            TcpMultiMachineLlmpHook::new(state, rt),
        ))
    }
}

impl<I> TcpMultiMachineState<I>
where
    I: Input,
{
    /// Read a [`TcpNodeMsg`] from a stream.
    /// Expects a message written by [`TcpMultiMachineState::write_msg`].
    /// If there is nothing to read from the stream, return asap with Ok(None).
    async fn read_msg(&mut self, stream: &mut TcpStream) -> Result<Option<TcpNodeMsg<I>>, Error> {
        // 0. Check if we should try to fetch something from the stream
        let mut dummy_byte: [u8; 1] = [0u8];
        let n_read = stream.read(&mut dummy_byte).await?;

        if n_read == 0 {
            return Ok(None); // Nothing to read from this stream
        }

        // we should always read the dummy byte at this point.
        assert_eq!(u8::from_le_bytes(dummy_byte), DUMMY_BYTE);

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

        Ok(Some(bitcode::deserialize(node_msg.as_ref())?))
    }

    /// Write a [`TcpNodeMsg`] to a stream.
    /// Can be read back using [`TcpMultiMachineState::read_msg`].
    async fn write_msg(
        &mut self,
        stream: &mut TcpStream,
        msg: &TcpNodeMsg<I>,
    ) -> Result<(), Error> {
        let serialized_msg = bitcode::serialize(msg)?;
        let msg_len = u32::to_le_bytes(serialized_msg.len() as u32);

        // 0. Write the dummy byte
        stream.write(&[DUMMY_BYTE]).await?;

        // 1. Write msg size
        stream.write(&msg_len).await?;

        // 2. Write msg
        stream.write(&serialized_msg).await?;

        Ok(())
    }

    async fn send_interesting_events_to_nodes<S: State>(
        &mut self,
        event: &Event<S::Input>,
    ) -> Result<(), Error> {
        if let Some(parent) = &mut self.parent {
            match self.write_msg(parent, TcpNodeMsg::new(event)).await {
                Err(_) => {
                    // most likely the parent disconnected. drop the connection
                    info!("The parent disconnected. We won't try to communicate with it again.");
                    self.parent.take();
                }
                Ok(_) => {} // write was successful, continue
            }
        }

        let mut ids_to_remove: Vec<NodeId> = Vec::new();
        for (child_id, child_stream) in &mut self.children {
            match self.write_msg(child_stream, event) {
                Err(_) => {
                    // most likely the child disconnected. drop the connection later on and continue.
                    info!("The child disconnected. We won't try to communicate with it again.");
                    ids_to_remove.push(child_id.clone());
                }
                Ok(_) => {} // write was successful, continue
            }
        }

        // Garbage collect disconnected children
        for id_to_remove in &ids_to_remove {
            self.children.remove(id_to_remove);
        }

        Ok(())
    }

    /// Flush the message queue from other nodes and add incoming events to the
    /// centralized event manager queue.
    pub(crate) async fn handle_new_messages_from_nodes<S: State>(
        &mut self,
        events: &mut Vec<Event<S::Input>>,
    ) -> Result<(), Error> {
        // Our (potential) parent could have something for us
        if let Some(parent) = &mut self.parent {
            match self.read_msg(parent).await {
                Err(_) => {
                    // most likely the parent disconnected. drop the connection
                    info!("The parent disconnected. We won't try to communicate with it again.");
                    self.parent.take();
                }
                Ok(Some(msg)) => {
                    // The parent has something for us, we store it
                    events.write().await.push(msg.event)
                }
                Ok(None) => {} // nothing from the parent, we continue
            }
        }

        // What about the (potential) children?
        let mut ids_to_remove: Vec<NodeId> = Vec::new();
        for (child_id, child_stream) in &mut self.children {
            match self.read_msg(child_stream) {
                Err(_) => {
                    // most likely the child disconnected. drop the connection later on and continue.
                    info!("The child disconnected. We won't try to communicate with it again.");
                    ids_to_remove.push(child_id.clone());
                }
                Ok(Some(msg)) => {
                    // A child has something for us, we store it
                    events.write().await.push(msg.event)
                }
                Ok(None) => {} // nothing from the parent, we continue
            }
        }

        // Garbage collect disconnected children
        for id_to_remove in &ids_to_remove {
            self.children.remove(id_to_remove);
        }

        Ok(())
    }
}
