use core::fmt::Display;
use std::{
    collections::HashMap,
    io, process,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock,
    },
    time::Duration,
    vec::Vec,
};

use enumflags2::{bitflags, BitFlags};
use libafl_bolts::{bolts_prelude::GzipCompressor, current_time, ownedref::OwnedRef, Error};
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
    events::{Event, TcpMultiMachineLlmpReceiverHook, TcpMultiMachineLlmpSenderHook},
    inputs::Input,
};

const LISTEN_PORT_BASE: u16 = 50000;

#[bitflags(default = SendToParent)]
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq)]
/// The node policy. It represents flags that can be applied to the node to change how it behaves.
pub enum NodePolicy {
    /// Send current node's interesting inputs to parent.
    SendToParent,
    /// Send current node's interesting inputs to children.
    SendToChildren,
}

const DUMMY_BYTE: u8 = 0x14;

// Use OwnedRef as much as possible here to avoid useless copies.
/// An owned TCP message for multi machine
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct OwnedTcpMultiMachineMsg<'a, I>
where
    I: Input,
{
    event: OwnedRef<'a, Event<I>>,
}

/// A TCP message for multi machine
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "I: serde::de::DeserializeOwned")]
pub struct TcpMultiMachineMsg<I>
where
    I: Input,
{
    event: Event<I>,
}

impl<'a, I> OwnedTcpMultiMachineMsg<'a, I>
where
    I: Input,
{
    /// Create a new [`OwnedTcpMultiMachineMsg`]. It is a more lightweight version of [`TcpMultiMachineMsg`]
    #[must_use]
    pub fn new(event: OwnedRef<'a, Event<I>>) -> Self {
        Self { event }
    }
}

impl<I> TcpMultiMachineMsg<I>
where
    I: Input,
{
    /// Create a new [`TcpMultiMachineMsg`].
    pub fn new(event: Event<I>) -> Self {
        Self { event }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
/// A `NodeId` (unused for now)
pub struct NodeId(pub u64);

impl NodeId {
    /// Generate a unique [`NodeId`].
    pub fn new() -> Self {
        static CTR: OnceLock<AtomicU64> = OnceLock::new();
        let ctr = CTR.get_or_init(|| AtomicU64::new(0));
        NodeId(ctr.fetch_add(1, Ordering::Relaxed))
    }
}

/// The state of the hook shared between the background threads and the main thread.
#[derive(Debug)]
#[allow(dead_code)]
pub struct TcpMultiMachineState<A, I>
where
    I: Input,
{
    node_descriptor: NodeDescriptor<A>,
    /// the parent to which the testcases should be forwarded when deemed interesting
    parent: Option<TcpStream>,
    /// The children who connected during the fuzzing session.
    children: HashMap<NodeId, TcpStream>, // The children who connected during the fuzzing session.
    old_events: Vec<Event<I>>,
    #[cfg(feature = "llmp_compression")]
    compressor: GzipCompressor,
}

/// The tree descriptor for the
#[derive(Debug, Clone, TypedBuilder)]
pub struct NodeDescriptor<A> {
    /// The parent address, if there is one.
    pub parent_addr: Option<A>,
    #[builder(default = 0)]
    /// The max amount of children
    pub max_nb_children: u16,
    #[builder(default = Duration::from_secs(60))]
    /// The timeout for connecting to parent
    pub timeout: Duration,
    /// Node flags
    #[builder(default_code = "BitFlags::default()")]
    pub flags: BitFlags<NodePolicy>, // The policy for shared messages between nodes.
}

/// A Multi-machine `broker_hooks` builder.
#[derive(Debug)]
pub struct TcpMultiMachineBuilder {
    _private: (),
}

impl TcpMultiMachineBuilder {
    /// Build a new couple [`TcpMultiMachineLlmpSenderHook`] / [`TcpMultiMachineLlmpReceiverHook`] from a [`NodeDescriptor`].
    /// Everything is initialized and ready to be used.
    /// Beware, the hooks should run in the same process as the one this function is called.
    /// This is because we spawn a tokio runtime underneath.
    /// Check `<https://github.com/tokio-rs/tokio/issues/4301>` for more details.
    pub fn build<A, I>(
        node_descriptor: NodeDescriptor<A>,
    ) -> Result<
        (
            TcpMultiMachineLlmpSenderHook<A, I>,
            TcpMultiMachineLlmpReceiverHook<A, I>,
        ),
        Error,
    >
    where
        A: Clone + Display + ToSocketAddrs + Send + Sync + 'static,
        I: Input + Send + Sync + 'static,
    {
        // Create the state of the hook. This will be shared with the background server, so we wrap
        // it with concurrent-safe objects
        let state = Arc::new(RwLock::new(TcpMultiMachineState {
            node_descriptor,
            parent: None,
            children: HashMap::default(),
            old_events: Vec::new(),
            #[cfg(feature = "llmp_compression")]
            compressor: GzipCompressor::new(),
        }));

        let rt =
            Arc::new(Runtime::new().map_err(|_| Error::unknown("Tokio runtime spawning failed"))?);

        unsafe {
            TcpMultiMachineState::init(&state.clone(), &rt.clone())?;
        }

        Ok((
            TcpMultiMachineLlmpSenderHook::new(state.clone(), rt.clone()),
            TcpMultiMachineLlmpReceiverHook::new(state, rt),
        ))
    }
}

impl<A, I> TcpMultiMachineState<A, I>
where
    A: Clone + Display + ToSocketAddrs + Send + Sync + 'static,
    I: Input + Send + Sync + 'static,
{
    /// Initializes the Multi-Machine state.
    ///
    /// # Safety
    ///
    /// This should be run **only once**, in the same process as the llmp hooks, and before the hooks
    /// are effectively used.
    unsafe fn init(self_mutex: &Arc<RwLock<Self>>, rt: &Arc<Runtime>) -> Result<(), Error> {
        let node_descriptor =
            rt.block_on(async { self_mutex.read().await.node_descriptor.clone() });

        // Try to connect to the parent if we should
        rt.block_on(async {
            let parent_mutex = self_mutex.clone();
            let mut parent_lock = parent_mutex.write().await;

            if let Some(parent_addr) = &parent_lock.node_descriptor.parent_addr {
                let timeout = current_time() + parent_lock.node_descriptor.timeout;

                parent_lock.parent = loop {
                    info!("Trying to connect to parent @ {}..", parent_addr);
                    match TcpStream::connect(parent_addr).await {
                        Ok(stream) => {
                            info!("Connected to parent @ {}", parent_addr);

                            break Some(stream);
                        }
                        Err(e) => {
                            if current_time() > timeout {
                                return Err(Error::os_error(e, "Unable to connect to parent"));
                            }
                        }
                    }

                    time::sleep(Duration::from_secs(1)).await;
                };
            }

            Ok(())
        })?;

        // Now, setup the background tasks for the children to connect to
        for i in 0..node_descriptor.max_nb_children {
            let bg_state = self_mutex.clone();
            info!("Spawning child task {}", i);
            let _handle: JoinHandle<Result<(), io::Error>> = rt.spawn(async move {
                info!("spawn worked");
                let port = LISTEN_PORT_BASE + i;
                let addr = format!("127.0.0.1:{port}");
                info!("Starting background child task on {addr}...");
                let listener = TcpListener::bind(addr).await?;
                let state = bg_state;

                loop {
                    info!("listening for children on {:?}...", listener);
                    let (stream, addr) = listener.accept().await?;
                    info!("{} joined the children.", addr);
                    let mut state_guard = state.write().await;

                    state_guard.children.insert(NodeId::new(), stream);
                    info!(
                        "[pid {}]{} added the child. nb children: {}",
                        process::id(),
                        addr,
                        state_guard.children.len()
                    );
                }
            });
        }

        Ok(())
    }

    /// The compressor
    #[cfg(feature = "llmp_compression")]
    pub fn compressor(&mut self) -> &GzipCompressor {
        &self.compressor
    }

    /// Read a [`TcpMultiMachineMsg`] from a stream.
    /// Expects a message written by [`TcpMultiMachineState::write_msg`].
    /// If there is nothing to read from the stream, return asap with Ok(None).
    async fn read_msg(stream: &mut TcpStream) -> Result<Option<TcpMultiMachineMsg<I>>, Error> {
        // 0. Check if we should try to fetch something from the stream
        let mut dummy_byte: [u8; 1] = [0u8];
        info!("Starting read msg...");
        let n_read = stream.try_read(&mut dummy_byte)?;
        info!("msg read.");

        if n_read == 0 {
            info!("No dummy byte received...");
            return Ok(None); // Nothing to read from this stream
        }

        info!("Received dummy byte!");

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

    /// Write an [`OwnedTcpMultiMachineMsg`] to a stream.
    /// Can be read back using [`TcpMultiMachineState::read_msg`].
    async fn write_msg<'a>(
        stream: &mut TcpStream,
        msg: &OwnedTcpMultiMachineMsg<'a, I>,
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

    pub(crate) async fn send_interesting_event_to_nodes(
        &mut self,
        event: &Event<I>,
    ) -> Result<(), Error> {
        info!("[multi-machine] Sending interesting events to nodes...");

        let msg = OwnedTcpMultiMachineMsg::new(OwnedRef::Ref(event));

        if self
            .node_descriptor
            .flags
            .intersects(NodePolicy::SendToParent)
        {
            if let Some(parent) = &mut self.parent {
                info!("Sending to parent...");
                if (Self::write_msg(parent, &msg).await).is_err() {
                    // most likely the parent disconnected. drop the connection
                    info!("The parent disconnected. We won't try to communicate with it again.");
                    self.parent.take();
                }
            }
        }

        if self
            .node_descriptor
            .flags
            .intersects(NodePolicy::SendToChildren)
        {
            let mut ids_to_remove: Vec<NodeId> = Vec::new();
            for (child_id, child_stream) in &mut self.children {
                info!("Sending to child...");
                if (Self::write_msg(child_stream, &msg).await).is_err() {
                    // most likely the child disconnected. drop the connection later on and continue.
                    info!("The child disconnected. We won't try to communicate with it again.");
                    ids_to_remove.push(*child_id);
                }
            }

            // Garbage collect disconnected children
            for id_to_remove in &ids_to_remove {
                info!("Child {:?} has been garbage collected.", id_to_remove);
                self.children.remove(id_to_remove);
            }
        }

        Ok(())
    }

    /// Flush the message queue from other nodes and add incoming events to the
    /// centralized event manager queue.
    pub(crate) async fn receive_new_messages_from_nodes(
        &mut self,
        events: &mut Vec<Event<I>>,
    ) -> Result<(), Error> {
        info!("Checking for new events from other nodes...");

        // Our (potential) parent could have something for us
        if let Some(parent) = &mut self.parent {
            info!("Receiving from parent...");
            match Self::read_msg(parent).await {
                Ok(Some(msg)) => {
                    info!("Received event from parent");
                    // The parent has something for us, we store it
                    events.push(msg.event);
                }

                Ok(None) => {
                    // nothing from the parent, we continue
                    info!("Nothing from parent");
                }

                Err(Error::OsError(io_err, _, _)) => {
                    if io_err.kind() == io::ErrorKind::WouldBlock {
                        // Expected, ignore.
                        info!("Would ignore, continue...");
                    } else {
                        // most likely the parent disconnected. drop the connection
                        info!(
                            "The parent disconnected. We won't try to communicate with it again."
                        );
                        self.parent.take();
                    }
                }
                Err(e) => {
                    info!("An error occured and was not expected.");
                    return Err(e);
                }
            }
        }

        // What about the (potential) children?
        let mut ids_to_remove: Vec<NodeId> = Vec::new();
        info!(
            "[pid {}] Nb children: {}",
            process::id(),
            self.children.len()
        );
        for (child_id, child_stream) in &mut self.children {
            info!("Receiving from child {:?}...", child_id);
            match Self::read_msg(child_stream).await {
                // Received a msg
                Ok(Some(msg)) => {
                    info!("Received event from child!");
                    // The parent has something for us, we store it
                    events.push(msg.event);
                }

                // Received nothing
                Ok(None) => {
                    info!("Nothing from child");
                    // nothing from the parent, we continue
                }

                // I/O error
                Err(Error::OsError(io_err, _, _)) => {
                    if io_err.kind() == io::ErrorKind::WouldBlock {
                        // Expected, ignore.
                        info!("Would ignore, continue...");
                    } else {
                        // most likely the parent disconnected. drop the connection
                        info!("The child disconnected. We won't try to communicate with it again.");
                        ids_to_remove.push(*child_id);
                    }
                }

                // Other error
                Err(e) => {
                    info!("An error occurred and was not expected.");
                    return Err(e);
                }
            }
        }

        // Garbage collect disconnected children
        for id_to_remove in &ids_to_remove {
            info!("Child {:?} has been garbage collected.", id_to_remove);
            self.children.remove(id_to_remove);
        }

        Ok(())
    }
}
