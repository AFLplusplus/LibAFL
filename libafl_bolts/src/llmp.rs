/*!
A library for low level message passing

To send new messages, the clients place a new message at the end of their
`client_out_mem`. If the current map is filled up, they place an end of page (`EOP`)
msg and alloc a new [`ShMem`].
Once the broker mapped this same page, it flags it as safe for unmapping.

```text
[client0]        [client1]    ...    [clientN]
  |                  |                 /
[client0_out] [client1_out] ... [clientN_out]
  |                 /                /
  |________________/                /
  |________________________________/
 \|/
[broker]
```

After the broker received a new message for clientN, (`clientN_out->current_id
!= last_message->message_id`) the broker will copy the message content to its
own, centralized page.

The clients periodically check (`current_broadcast_shmem->current_id !=
last_message->message_id`) for new incoming messages. If the page is filled up,
the broker instead creates a new page and places an end of page (`EOP`)
message in its queue. The `EOP` buf contains the new description to
access the shared map. The clients then switch over to read from that new
current map.

```text
[broker]
  |
[current_broadcast_shmem]
  |
  |___________________________________
  |_________________                  \
  |                 \                  \
  |                  |                  |
 \|/                \|/                \|/
[client0]        [client1]    ...    [clientN]
```

In the future, if we would need zero copy, the `current_broadcast_shmem` could instead
list the `client_out_shmem` ID an offset for each message. In that case, the clients
also need to create a new [`ShMem`] each time their bufs are filled up.


To use, you will have to create a broker using [`LlmpBroker::new()`].
Then, create some [`LlmpClient`]`s` in other threads and register them
with the main thread using [`LlmpBroker::register_client`].
Finally, call [`LlmpBroker::loop_forever()`].

For broker2broker communication, all messages are forwarded via network sockets.

Check out the `llmp_test` example in ./examples, or build it with `cargo run --example llmp_test`.

*/

#[cfg(feature = "std")]
use alloc::string::ToString;
use alloc::{string::String, vec::Vec};
#[cfg(not(target_pointer_width = "64"))]
use core::sync::atomic::AtomicU32;
#[cfg(target_pointer_width = "64")]
use core::sync::atomic::AtomicU64;
use core::{
    cmp::max,
    fmt::Debug,
    hint,
    mem::size_of,
    num::NonZeroUsize,
    ops::{BitAnd, BitOr, Not},
    ptr, slice,
    sync::atomic::{fence, AtomicU16, Ordering},
    time::Duration,
};
#[cfg(feature = "std")]
use std::{
    env,
    io::{ErrorKind, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::mpsc::channel,
    thread,
};

#[cfg(all(debug_assertions, feature = "llmp_debug", feature = "std"))]
use backtrace::Backtrace;
#[cfg(all(unix, feature = "std"))]
#[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
use nix::sys::socket::{self, sockopt::ReusePort};
use serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use crate::current_time;
#[cfg(all(unix, not(miri)))]
use crate::os::unix_signals::setup_signal_handler;
#[cfg(unix)]
use crate::os::unix_signals::{siginfo_t, ucontext_t, Handler, Signal};
#[cfg(all(windows, feature = "std"))]
use crate::os::windows_exceptions::{setup_ctrl_handler, CtrlHandler};
use crate::{
    shmem::{ShMem, ShMemDescription, ShMemId, ShMemProvider},
    ClientId, Error,
};

/// The default timeout in seconds after which a client will be considered stale, and removed.
pub const DEFAULT_CLIENT_TIMEOUT_SECS: Duration = Duration::from_secs(300);

/// The max number of pages a [`client`] may have mapped that were not yet read by the [`broker`]
/// Usually, this value should not exceed `1`, else the broker cannot keep up with the amount of incoming messages.
/// Instead of increasing this value, you may consider sending new messages at a lower rate, else your Sender will eventually `OOM`.
const LLMP_CFG_MAX_PENDING_UNREAD_PAGES: usize = 3;
/// We'll start off with 256 megabyte maps per fuzzer client
#[cfg(not(feature = "llmp_small_maps"))]
const LLMP_CFG_INITIAL_MAP_SIZE: usize = 1 << 28;
/// If the `llmp_small_maps` feature is set, we start off with 1 meg.
#[cfg(feature = "llmp_small_maps")]
const LLMP_CFG_INITIAL_MAP_SIZE: usize = 1 << 20;
/// What byte count to align messages to
/// [`LlmpMsg`] sizes (including header) will always be rounded up to be a multiple of this value.
const LLMP_CFG_ALIGNNMENT: usize = 64;

/// A msg fresh from the press: No tag got sent by the user yet
const LLMP_TAG_UNSET: Tag = Tag(0xDEADAF);
/// This message should not exist yet. Some bug in unsafe code!
const LLMP_TAG_UNINITIALIZED: Tag = Tag(0xA143AF11);
/// The end of page message
/// When receiving this, a new sharedmap needs to be allocated.
const LLMP_TAG_END_OF_PAGE: Tag = Tag(0xAF1E0F1);
/// A new client for this broker got added.
const LLMP_TAG_NEW_SHM_CLIENT: Tag = Tag(0xC11E471);
/// The sender on this map is exiting (if broker exits, clients should exit gracefully);
const LLMP_TAG_EXITING: Tag = Tag(0x13C5171);
/// Client gave up as the receiver/broker was too slow
const LLMP_SLOW_RECEIVER_PANIC: Tag = Tag(0x70051041);

/// Unused...
pub const LLMP_FLAG_INITIALIZED: Flags = Flags(0x0);
/// This message was compressed in transit
pub const LLMP_FLAG_COMPRESSED: Flags = Flags(0x1);
/// From another broker.
pub const LLMP_FLAG_FROM_B2B: Flags = Flags(0x2);

/// Timt the broker 2 broker connection waits for incoming data,
/// before checking for own data to forward again.
const _LLMP_B2B_BLOCK_TIME: Duration = Duration::from_millis(3_000);

/// If broker2broker is enabled, bind to public IP
#[cfg(feature = "llmp_bind_public")]
const _LLMP_BIND_ADDR: &str = "0.0.0.0";

/// If broker2broker is disabled, bind to localhost
#[cfg(not(feature = "llmp_bind_public"))]
const _LLMP_BIND_ADDR: &str = "127.0.0.1";

/// LLMP Client connects to this address
const _LLMP_CONNECT_ADDR: &str = "127.0.0.1";

/// An env var of this value indicates that the set value was a NULL PTR
const _NULL_ENV_STR: &str = "_NULL";

/// Magic indicating that a got initialized correctly
const PAGE_INITIALIZED_MAGIC: u64 = 0x1A1A1A1A1A1A1AF1;

/// Magic indicating that a got deinitialized correctly, after use
const PAGE_DEINITIALIZED_MAGIC: u64 = 0xDEADC0FEAF1BEEF1;

/// Size of a new page message, header, payload, and alignment
const EOP_MSG_SIZE: usize =
    llmp_align(size_of::<LlmpMsg>() + size_of::<LlmpPayloadSharedMapInfo>());
/// The header length of a llmp page in a shared map (until messages start)
const LLMP_PAGE_HEADER_LEN: usize = size_of::<LlmpPage>();

/// The llmp broker registers a signal handler for cleanups on `SIGINT`.
#[cfg(any(unix, all(windows, feature = "std")))]
static mut LLMP_SIGHANDLER_STATE: LlmpShutdownSignalHandler = LlmpShutdownSignalHandler {
    shutting_down: false,
};

/// TAGs used throughout llmp
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tag(pub u32);

impl Debug for Tag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("Tag({:X})", self.0))
    }
}

/// The broker ID, for broker 2 broker communication.
#[repr(transparent)]
#[derive(
    Debug, Default, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct BrokerId(pub u32);
/// The flags, indicating, for example, enabled compression.
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Flags(pub u32);

impl Debug for Flags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("Flags{:x}( ", self.0))?;
        // Initialized is the default value, no need to print.
        if *self & LLMP_FLAG_COMPRESSED == LLMP_FLAG_COMPRESSED {
            f.write_str("COMPRESSED")?;
        }
        if *self & LLMP_FLAG_FROM_B2B == LLMP_FLAG_FROM_B2B {
            f.write_str("FROM_B2B")?;
        }
        f.write_str(" )")
    }
}

impl BitAnd for Flags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitOr for Flags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl Not for Flags {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

/// The message ID, an ever-increasing number, unique only to a sharedmap/page.
#[cfg(target_pointer_width = "64")]
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MessageId(u64);
/// The message ID, an ever-increasing number, unique only to a sharedmap/page.
#[cfg(not(target_pointer_width = "64"))]
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MessageId(u32);

/// This is for the server the broker will spawn.
/// If an llmp connection is local - use sharedmaps
/// or remote (broker2broker) - forwarded via tcp
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TcpRequest {
    /// We would like to be a local client.
    LocalClientHello {
        /// The sharedmem description of the connecting client.
        shmem_description: ShMemDescription,
    },
    /// We would like to establish a b2b connection.
    RemoteBrokerHello {
        /// The hostname of our broker, trying to connect.
        hostname: String,
    },
}

impl TryFrom<&Vec<u8>> for TcpRequest {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Error> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

impl TryFrom<Vec<u8>> for TcpRequest {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Error> {
        Ok(postcard::from_bytes(&bytes)?)
    }
}

/// Messages for broker 2 broker connection.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpRemoteNewMessage {
    // The client ID of the original broker
    client_id: ClientId,
    // The message tag
    tag: Tag,
    // The flags
    flags: Flags,
    // The actual content of the message
    payload: Vec<u8>,
}

impl TryFrom<&Vec<u8>> for TcpRemoteNewMessage {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Error> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

impl TryFrom<Vec<u8>> for TcpRemoteNewMessage {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Error> {
        Ok(postcard::from_bytes(&bytes)?)
    }
}

/// Responses for requests to the server.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TcpResponse {
    /// After receiving a new connection, the broker immediately sends a Hello.
    BrokerConnectHello {
        /// The broker page a new local client can listen on
        broker_shmem_description: ShMemDescription,
        /// This broker's hostname
        hostname: String,
    },
    /// Notify the client on the other side that it has been accepted.
    LocalClientAccepted {
        /// The `ClientId` this client should send messages as.
        /// Mainly used for client-side deduplication of incoming messages
        client_id: ClientId,
    },
    /// Notify the remote broker has been accepted.
    RemoteBrokerAccepted {
        /// The broker id of this element
        broker_id: BrokerId,
    },
    /// Something went wrong when processing the request.
    Error {
        /// Error description
        description: String,
    },
}

impl TryFrom<&Vec<u8>> for TcpResponse {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Error> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

impl TryFrom<Vec<u8>> for TcpResponse {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Error> {
        Ok(postcard::from_bytes(&bytes)?)
    }
}

/// Abstraction for listeners
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum Listener {
    /// Listener listening on `tcp`.
    Tcp(TcpListener),
}

/// A listener stream abstraction
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum ListenerStream {
    /// Listener listening on `tcp`.
    Tcp(TcpStream, SocketAddr),
    /// No listener provided.
    Empty(),
}

#[cfg(feature = "std")]
impl Listener {
    fn accept(&self) -> ListenerStream {
        match self {
            Listener::Tcp(inner) => match inner.accept() {
                Ok(res) => ListenerStream::Tcp(res.0, res.1),
                Err(err) => {
                    log::warn!("Ignoring failed accept: {err:?}");
                    ListenerStream::Empty()
                }
            },
        }
    }
}

/// Get sharedmem from a page
#[inline]
#[allow(clippy::cast_ptr_alignment)]
unsafe fn shmem2page_mut<SHM: ShMem>(afl_shmem: &mut SHM) -> *mut LlmpPage {
    afl_shmem.as_mut_slice().as_mut_ptr() as *mut LlmpPage
}

/// Get sharedmem from a page
#[inline]
#[allow(clippy::cast_ptr_alignment)]
unsafe fn shmem2page<SHM: ShMem>(afl_shmem: &SHM) -> *const LlmpPage {
    afl_shmem.as_slice().as_ptr() as *const LlmpPage
}

/// Return, if a msg is contained in the current page
#[inline]
unsafe fn llmp_msg_in_page(page: *const LlmpPage, msg: *const LlmpMsg) -> bool {
    /* DBG("llmp_msg_in_page %p within %p-%p\n", msg, page, page + page->size_total); */
    (page as *const u8) < msg as *const u8
        && (page as *const u8).add((*page).size_total) > msg as *const u8
}

/// Align the page to `LLMP_CFG_ALIGNNMENT=64` bytes
#[inline]
const fn llmp_align(to_align: usize) -> usize {
    // check if we need to align first
    if LLMP_CFG_ALIGNNMENT == 0 {
        return to_align;
    }
    // Then do the alignment
    let modulo = to_align % LLMP_CFG_ALIGNNMENT;
    if modulo == 0 {
        to_align
    } else {
        to_align + LLMP_CFG_ALIGNNMENT - modulo
    }
}

/// Reads the stored message offset for the given `env_name` (by appending `_OFFSET`).
/// If the content of the env is `_NULL`, returns [`Option::None`].
#[cfg(feature = "std")]
#[inline]
fn msg_offset_from_env(env_name: &str) -> Result<Option<u64>, Error> {
    let msg_offset_str = env::var(format!("{env_name}_OFFSET"))?;
    Ok(if msg_offset_str == _NULL_ENV_STR {
        None
    } else {
        Some(msg_offset_str.parse()?)
    })
}

/// Bind to a tcp port on the [`_LLMP_BIND_ADDR`] (local, or global)
/// on a given `port`.
/// Will set `SO_REUSEPORT` on unix.
#[cfg(feature = "std")]
fn tcp_bind(port: u16) -> Result<TcpListener, Error> {
    let listener = TcpListener::bind((_LLMP_BIND_ADDR, port))?;

    #[cfg(unix)]
    #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
    socket::setsockopt(&listener, ReusePort, &true)?;

    Ok(listener)
}

/// Send one message as `u32` len and `[u8;len]` bytes
#[cfg(feature = "std")]
fn send_tcp_msg<T>(stream: &mut TcpStream, msg: &T) -> Result<(), Error>
where
    T: Serialize,
{
    let msg = postcard::to_allocvec(msg)?;
    if msg.len() > u32::MAX as usize {
        return Err(Error::illegal_state(format!(
            "Trying to send message a tcp message > u32! (size: {})",
            msg.len()
        )));
    }

    #[cfg(feature = "llmp_debug")]
    log::trace!("LLMP TCP: Sending {} bytes", msg.len());

    let size_bytes = (msg.len() as u32).to_be_bytes();
    stream.write_all(&size_bytes)?;
    stream.write_all(&msg)?;

    #[cfg(feature = "llmp_debug")]
    log::trace!("LLMP TCP: Sending {} bytes finished.", msg.len());

    Ok(())
}

/// Receive one message of `u32` len and `[u8; len]` bytes
#[cfg(feature = "std")]
fn recv_tcp_msg(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    // Always receive one be u32 of size, then the command.

    #[cfg(feature = "llmp_debug")]
    log::trace!(
        "LLMP TCP: Waiting for packet... (Timeout: {:?})",
        stream.read_timeout().unwrap_or(None)
    );

    let mut size_bytes = [0_u8; 4];
    stream.read_exact(&mut size_bytes)?;
    let size = u32::from_be_bytes(size_bytes);
    let mut bytes = vec![0; size.try_into().unwrap()];

    #[cfg(feature = "llmp_debug")]
    log::trace!("LLMP TCP: Receiving payload of size {size}");

    stream
        .read_exact(&mut bytes)
        .expect("Failed to read message body");
    Ok(bytes)
}

/// In case we don't have enough space, make sure the next page will be large
/// enough. For now, we want to have at least enough space to store 2 of the
/// largest messages we encountered (plus message one `new_page` message).
#[inline]
fn next_shmem_size(max_alloc: usize) -> usize {
    max(
        max_alloc * 2 + EOP_MSG_SIZE + LLMP_PAGE_HEADER_LEN,
        LLMP_CFG_INITIAL_MAP_SIZE - 1,
    )
    .next_power_of_two()
}

/// Initialize a new `llmp_page`. The size should be relative to
/// `llmp_page->messages`
///
/// # Safety
/// Will write to the raw SHM page header, should be safe for correct [`ShMem`] implementations
unsafe fn llmp_page_init<SHM: ShMem>(shmem: &mut SHM, sender_id: ClientId, allow_reinit: bool) {
    #[cfg(feature = "llmp_debug")]
    log::trace!("llmp_page_init: shmem {:?}", &shmem);
    let map_size = shmem.len();
    let page = shmem2page_mut(shmem);
    #[cfg(feature = "llmp_debug")]
    log::trace!("llmp_page_init: page {:?}", &(*page));

    if !allow_reinit {
        assert!(
            (*page).magic != PAGE_INITIALIZED_MAGIC,
            "Tried to initialize page {page:?} twice (for shmem {shmem:?})"
        );
    }

    (*page).magic = PAGE_INITIALIZED_MAGIC;
    (*page).sender_id = sender_id;
    (*page).current_msg_id.store(0, Ordering::Relaxed);
    (*page).max_alloc_size = 0;
    // Don't forget to subtract our own header size
    (*page).size_total = map_size - LLMP_PAGE_HEADER_LEN;
    (*page).size_used = 0;
    (*(*page).messages.as_mut_ptr()).message_id = MessageId(0);
    (*(*page).messages.as_mut_ptr()).tag = LLMP_TAG_UNSET;
    (*page).receivers_joined_count.store(0, Ordering::Release);
    (*page).receivers_left_count.store(0, Ordering::Relaxed);
    assert!((*page).size_total != 0);
}

/// Get the next pointer and make sure it's in the current page, and has enough space.
///
/// # Safety
/// Will dereference `last_msg`
#[inline]
unsafe fn llmp_next_msg_ptr_checked<SHM: ShMem>(
    map: &mut LlmpSharedMap<SHM>,
    last_msg: *const LlmpMsg,
    alloc_size: usize,
) -> Result<*mut LlmpMsg, Error> {
    let page = map.page_mut();
    let map_size = map.shmem.as_slice().len();
    let msg_begin_min = (page as *const u8).add(size_of::<LlmpPage>());
    // We still need space for this msg (alloc_size).
    let msg_begin_max = (page as *const u8).add(map_size - alloc_size);
    let next = _llmp_next_msg_ptr(last_msg);
    let next_ptr = next as *const u8;
    if next_ptr >= msg_begin_min && next_ptr <= msg_begin_max {
        Ok(next)
    } else {
        Err(Error::illegal_state(format!(
            "Inconsistent data on sharedmap, or Bug (next_ptr was {:x}, sharedmap page was {:x})",
            next_ptr as usize, page as usize
        )))
    }
}

/// Pointer to the message behind the last message
/// The messages are padded, so accesses will be aligned properly.
///
/// # Safety
/// Will dereference the `last_msg` ptr
#[inline]
#[allow(clippy::cast_ptr_alignment)]
unsafe fn _llmp_next_msg_ptr(last_msg: *const LlmpMsg) -> *mut LlmpMsg {
    /* DBG("_llmp_next_msg_ptr %p %lu + %lu\n", last_msg, last_msg->buf_len_padded, sizeof(llmp_message)); */
    (last_msg as *mut u8)
        .add(size_of::<LlmpMsg>())
        .add((*last_msg).buf_len_padded as usize) as *mut LlmpMsg
}

/// Description of a shared map.
/// May be used to restore the map by id.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct LlmpDescription {
    /// Info about the [`ShMem`] in use
    shmem: ShMemDescription,
    /// The last message sent or received, depnding on page type
    last_message_offset: Option<u64>,
}

#[derive(Copy, Clone, Debug)]
/// Result of an LLMP Message hook
pub enum LlmpMsgHookResult {
    /// This has been handled in the broker. No need to forward.
    Handled,
    /// Forward this to the clients. We are not done here.
    ForwardToClients,
}

/// Message sent over the "wire"
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct LlmpMsg {
    /// A tag
    pub tag: Tag, //u32
    /// Sender of this message
    pub sender: ClientId, //u32
    /// ID of another Broker, for b2b messages
    pub broker: BrokerId, //u32
    /// flags, currently only used for indicating compression
    pub flags: Flags, //u32
    /// The message ID, unique per page
    pub message_id: MessageId, //u64 on 64 bit, else u32
    /// Buffer length as specified by the user
    pub buf_len: u64,
    /// (Actual) buffer length after padding
    // Padding makes sure the next msg is aligned.
    pub buf_len_padded: u64,
    /// The actual payload buf
    // We try to keep the start of buf 64-bit aligned!
    pub buf: [u8; 0],
}

/// The message we receive
impl LlmpMsg {
    /// Gets the buffer from this message as slice, with the corrent length.
    /// # Safety
    /// This is unsafe if somebody has access to shared mem pages on the system.
    #[must_use]
    pub unsafe fn as_slice_unsafe(&self) -> &[u8] {
        slice::from_raw_parts(self.buf.as_ptr(), self.buf_len as usize)
    }

    /// Gets the buffer from this message as slice, with the correct length.
    #[inline]
    pub fn try_as_slice<SHM: ShMem>(&self, map: &mut LlmpSharedMap<SHM>) -> Result<&[u8], Error> {
        unsafe {
            if self.in_shmem(map) {
                Ok(self.as_slice_unsafe())
            } else {
                Err(Error::illegal_state("Current message not in page. The sharedmap get tampered with or we have a BUG."))
            }
        }
    }

    /// Returns `true`, if the pointer is, indeed, in the page of this shared map.
    #[inline]
    pub fn in_shmem<SHM: ShMem>(&self, map: &mut LlmpSharedMap<SHM>) -> bool {
        let map_size = map.shmem.as_slice().len();
        let buf_ptr = self.buf.as_ptr();
        let len = self.buf_len_padded as usize + size_of::<LlmpMsg>();
        unsafe {
            buf_ptr > (map.page_mut() as *const u8).add(size_of::<LlmpPage>())
                && buf_ptr.add(len).sub(size_of::<LlmpPage>())
                    <= (map.page_mut() as *const u8).add(map_size)
        }
    }
}

/// An Llmp instance
#[derive(Debug)]
pub enum LlmpConnection<SP>
where
    SP: ShMemProvider + 'static,
{
    /// A broker and a thread using this tcp background thread
    IsBroker {
        /// The [`LlmpBroker`] of this [`LlmpConnection`].
        broker: LlmpBroker<SP>,
    },
    /// A client, connected to the port
    IsClient {
        /// The [`LlmpClient`] of this [`LlmpConnection`].
        client: LlmpClient<SP>,
    },
}

impl<SP> LlmpConnection<SP>
where
    SP: ShMemProvider,
{
    #[cfg(feature = "std")]
    /// Creates either a broker, if the tcp port is not bound, or a client, connected to this port.
    pub fn on_port(shmem_provider: SP, port: u16, client_timeout: Duration) -> Result<Self, Error> {
        match tcp_bind(port) {
            Ok(listener) => {
                // We got the port. We are the broker! :)
                log::info!("We're the broker");

                let mut broker = LlmpBroker::new(shmem_provider, client_timeout)?;
                let _listener_thread = broker.launch_listener(Listener::Tcp(listener))?;
                Ok(LlmpConnection::IsBroker { broker })
            }
            Err(Error::OsError(e, ..)) if e.kind() == ErrorKind::AddrInUse => {
                // We are the client :)
                log::info!("We're the client (internal port already bound by broker, {e:#?})");
                Ok(LlmpConnection::IsClient {
                    client: LlmpClient::create_attach_to_tcp(shmem_provider, port)?,
                })
            }
            Err(e) => {
                log::error!("{e:?}");
                Err(e)
            }
        }
    }

    /// Creates a new broker on the given port
    #[cfg(feature = "std")]
    pub fn broker_on_port(
        shmem_provider: SP,
        port: u16,
        client_timeout: Duration,
    ) -> Result<Self, Error> {
        Ok(LlmpConnection::IsBroker {
            broker: LlmpBroker::create_attach_to_tcp(shmem_provider, port, client_timeout)?,
        })
    }

    /// Creates a new client on the given port
    #[cfg(feature = "std")]
    pub fn client_on_port(shmem_provider: SP, port: u16) -> Result<Self, Error> {
        Ok(LlmpConnection::IsClient {
            client: LlmpClient::create_attach_to_tcp(shmem_provider, port)?,
        })
    }

    /// Describe this in a reproducable fashion, if it's a client
    pub fn describe(&self) -> Result<LlmpClientDescription, Error> {
        Ok(match self {
            LlmpConnection::IsClient { client } => client.describe()?,
            LlmpConnection::IsBroker { .. } => todo!("Only client can be described atm."),
        })
    }

    /// Recreate an existing client from the stored description
    pub fn existing_client_from_description(
        shmem_provider: SP,
        description: &LlmpClientDescription,
    ) -> Result<LlmpConnection<SP>, Error> {
        Ok(LlmpConnection::IsClient {
            client: LlmpClient::existing_client_from_description(shmem_provider, description)?,
        })
    }

    /// Sends the given buffer over this connection, no matter if client or broker.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        match self {
            LlmpConnection::IsBroker { broker } => broker.send_buf(tag, buf),
            LlmpConnection::IsClient { client } => client.send_buf(tag, buf),
        }
    }

    /// Send the `buf` with given `flags`.
    pub fn send_buf_with_flags(&mut self, tag: Tag, buf: &[u8], flags: Flags) -> Result<(), Error> {
        match self {
            LlmpConnection::IsBroker { broker } => broker.send_buf_with_flags(tag, flags, buf),
            LlmpConnection::IsClient { client } => client.send_buf_with_flags(tag, flags, buf),
        }
    }
}

/// Contents of the share mem pages, used by llmp internally
#[derive(Debug)]
#[repr(C)]
pub struct LlmpPage {
    /// to check if this page got initialized properly
    pub magic: u64,
    /// The id of the sender
    pub sender_id: ClientId,
    /// Set to != 1 by the receiver, once it got mapped.
    /// It's not safe for the sender to unmap this page before
    /// (The os may have tidied up the memory when the receiver starts to map)
    pub receivers_joined_count: AtomicU16,
    /// Set to != 1 by the receiver, once it left again after joining.
    /// It's not safe for the sender to re-map this page before this is equal to `receivers_joined_count`
    pub receivers_left_count: AtomicU16,
    #[cfg(target_pointer_width = "64")]
    /// The current message ID
    pub current_msg_id: AtomicU64,
    #[cfg(not(target_pointer_width = "64"))]
    /// The current message ID
    pub current_msg_id: AtomicU32,
    /// How much space is available on this page in bytes
    pub size_total: usize,
    /// How much space is used on this page in bytes
    pub size_used: usize,
    /// The maximum amount of bytes that ever got allocated on this page in one go.
    /// An inidactor of what to use as size for future pages
    pub max_alloc_size: usize,
    /// Pointer to the messages, from here on.
    pub messages: [LlmpMsg; 0],
}

impl LlmpPage {
    #[inline]
    fn receiver_joined(&mut self) {
        let receivers_joined_count = &mut self.receivers_joined_count;
        //receivers_joined_count.fetch_add(1, Ordering::Relaxed);
        receivers_joined_count.store(1, Ordering::Relaxed);
    }

    #[inline]
    fn receiver_left(&mut self) {
        let receivers_joined_count = &mut self.receivers_joined_count;
        //receivers_joined_count.fetch_add(1, Ordering::Relaxed);
        receivers_joined_count.store(1, Ordering::Relaxed);
    }
}

/// Message payload when a client got added */
/// This is an internal message!
/// [`LLMP_TAG_END_OF_PAGE_V1`]
#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct LlmpPayloadSharedMapInfo {
    /// The map size
    pub map_size: usize,
    /// The id of this map, as 0-terminated c string of at most 19 chars
    pub shm_str: [u8; 20],
}

/// Sending end on a (unidirectional) sharedmap channel
#[derive(Debug)]
pub struct LlmpSender<SP>
where
    SP: ShMemProvider,
{
    /// ID of this sender.
    id: ClientId,
    /// Ref to the last message this sender sent on the last page.
    /// If null, a new page (just) started.
    last_msg_sent: *const LlmpMsg,
    /// A vec of page wrappers, each containing an initialized [`ShMem`]
    out_shmems: Vec<LlmpSharedMap<SP::ShMem>>,
    /// A vec of pages that we previously used, but that have served its purpose
    /// (no potential receivers are left).
    /// Instead of freeing them, we keep them around to potentially reuse them later,
    /// if they are still large enough.
    /// This way, the OS doesn't have to spend time zeroing pages, and getting rid of our old pages
    unused_shmem_cache: Vec<LlmpSharedMap<SP::ShMem>>,
    /// If true, pages will never be pruned.
    /// The broker uses this feature.
    /// By keeping the message history around,
    /// new clients may join at any time in the future.
    keep_pages_forever: bool,
    /// True, if we allocatd a message, but didn't call [`Self::send()`] yet
    has_unsent_message: bool,
    /// The sharedmem provider to get new sharaed maps if we're full
    shmem_provider: SP,
}

/// An actor on the sending part of the shared map
impl<SP> LlmpSender<SP>
where
    SP: ShMemProvider,
{
    /// Create a new [`LlmpSender`] using a given [`ShMemProvider`], and `id`.
    /// If `keep_pages_forever` is `true`, `ShMem` will never be freed.
    /// If it is `false`, the pages will be unmapped once they are full, and have been mapped by at least one `LlmpReceiver`.
    pub fn new(
        mut shmem_provider: SP,
        id: ClientId,
        keep_pages_forever: bool,
    ) -> Result<Self, Error> {
        #[cfg(feature = "llmp_debug")]
        log::info!(
            "PID: {:#?} Initializing LlmpSender {:#?}",
            std::process::id(),
            id
        );
        Ok(Self {
            id,
            last_msg_sent: ptr::null_mut(),
            out_shmems: vec![LlmpSharedMap::new(
                id,
                shmem_provider.new_shmem(LLMP_CFG_INITIAL_MAP_SIZE)?,
            )],
            // drop pages to the broker if it already read them
            keep_pages_forever,
            has_unsent_message: false,
            shmem_provider,
            unused_shmem_cache: vec![],
        })
    }

    /// ID of this sender.
    #[must_use]
    pub fn id(&self) -> ClientId {
        self.id
    }

    /// Completely reset the current sender map.
    /// Afterwards, no receiver should read from it at a different location.
    /// This is only useful if all connected llmp parties start over, for example after a crash.
    ///
    /// # Safety
    /// Only safe if you really really restart the page on everything connected
    /// No receiver should read from this page at a different location.
    pub unsafe fn reset(&mut self) {
        llmp_page_init(
            &mut self.out_shmems.last_mut().unwrap().shmem,
            self.id,
            true,
        );
        self.last_msg_sent = ptr::null_mut();
    }

    /// Reads the stored sender / client id for the given `env_name` (by appending `_CLIENT_ID`).
    /// If the content of the env is `_NULL`, returns [`Option::None`].
    #[cfg(feature = "std")]
    #[inline]
    fn client_id_from_env(env_name: &str) -> Result<Option<ClientId>, Error> {
        let client_id_str = env::var(format!("{env_name}_CLIENT_ID"))?;
        Ok(if client_id_str == _NULL_ENV_STR {
            None
        } else {
            Some(ClientId(client_id_str.parse()?))
        })
    }

    /// Writes the `id` to an env var
    #[cfg(feature = "std")]
    fn client_id_to_env(env_name: &str, id: ClientId) {
        env::set_var(format!("{env_name}_CLIENT_ID"), format!("{}", id.0));
    }

    /// Reattach to a vacant `out_shmem`, to with a previous sender stored the information in an env before.
    #[cfg(feature = "std")]
    pub fn on_existing_from_env(mut shmem_provider: SP, env_name: &str) -> Result<Self, Error> {
        let msg_sent_offset = msg_offset_from_env(env_name)?;
        let mut ret = Self::on_existing_shmem(
            shmem_provider.clone(),
            shmem_provider.existing_from_env(env_name)?,
            msg_sent_offset,
        )?;
        ret.id = Self::client_id_from_env(env_name)?.unwrap_or_default();
        #[cfg(feature = "llmp_debug")]
        log::info!(
            "PID: {:#?} Initializing LlmpSender from on_existing_from_env {:#?}",
            std::process::id(),
            &ret.id
        );
        Ok(ret)
    }

    /// Store the info to this sender to env.
    /// A new client can reattach to it using [`LlmpSender::on_existing_from_env()`].
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) -> Result<(), Error> {
        let current_out_shmem = self.out_shmems.last().unwrap();
        current_out_shmem.shmem.write_to_env(env_name)?;
        Self::client_id_to_env(env_name, self.id);
        unsafe { current_out_shmem.msg_to_env(self.last_msg_sent, env_name) }
    }

    /// Waits for this sender to be save to unmap.
    /// If a receiver is involved, this function should always be called.
    pub fn await_safe_to_unmap_blocking(&self) {
        #[cfg(feature = "std")]
        let mut ctr = 0_u16;
        loop {
            if self.safe_to_unmap() {
                return;
            }
            hint::spin_loop();
            // We log that we're looping -> see when we're blocking.
            #[cfg(feature = "std")]
            {
                ctr = ctr.wrapping_add(1);
                if ctr == 0 {
                    log::info!("Awaiting safe_to_unmap_blocking");
                }
            }
        }
    }

    /// If we are allowed to unmap this client
    pub fn safe_to_unmap(&self) -> bool {
        let current_out_shmem = self.out_shmems.last().unwrap();
        unsafe {
            // log::info!("Reading safe_to_unmap from {:?}", current_out_shmem.page() as *const _);
            (*current_out_shmem.page())
                .receivers_joined_count
                .load(Ordering::Relaxed)
                >= 1
        }
    }

    /// For debug purposes: Mark save to unmap, even though it might not have been read by a receiver yet.
    /// # Safety
    /// If this method is called, the page may be unmapped before it is read by any receiver.
    pub unsafe fn mark_safe_to_unmap(&mut self) {
        (*self.out_shmems.last_mut().unwrap().page_mut()).receiver_joined();
    }

    /// Reattach to a vacant `out_shmem`.
    /// It is essential, that the receiver (or someone else) keeps a pointer to this map
    /// else reattach will get a new, empty page, from the OS, or fail.
    pub fn on_existing_shmem(
        shmem_provider: SP,
        current_out_shmem: SP::ShMem,
        last_msg_sent_offset: Option<u64>,
    ) -> Result<Self, Error> {
        let mut out_shmem = LlmpSharedMap::existing(current_out_shmem);
        let last_msg_sent = match last_msg_sent_offset {
            Some(offset) => out_shmem.msg_from_offset(offset)?,
            None => ptr::null_mut(),
        };

        let client_id = unsafe { (*out_shmem.page()).sender_id };
        #[cfg(feature = "llmp_debug")]
        log::info!(
            "PID: {:#?} Initializing LlmpSender from on_existing_shmem {:#?}",
            std::process::id(),
            &client_id
        );
        Ok(Self {
            id: client_id,
            last_msg_sent,
            out_shmems: vec![out_shmem],
            // drop pages to the broker if it already read them
            keep_pages_forever: false,
            has_unsent_message: false,
            shmem_provider,
            unused_shmem_cache: vec![],
        })
    }

    /// For non zero-copy, we want to get rid of old pages with duplicate messages in the client
    /// eventually. This function This function sees if we can deallocate older pages.
    /// The broker would have informed us by setting the safe_to_unmap-flag.
    unsafe fn prune_old_pages(&mut self) {
        // Exclude the current page by splitting of the last element for this iter
        let mut unmap_until_excl = 0;
        for map in self.out_shmems.split_last_mut().unwrap().1 {
            if (*map.page()).receivers_joined_count.load(Ordering::Acquire) == 0 {
                // The broker didn't read this page yet, no more pages to unmap.
                break;
            }
            unmap_until_excl += 1;
        }

        if unmap_until_excl == 0 && self.out_shmems.len() > LLMP_CFG_MAX_PENDING_UNREAD_PAGES {
            // Looks like nobody is listening to our pages anymore! :/
            // The n old pages have not been touched yet.
            // We send one last information to the broker before quitting.
            self.send_buf(LLMP_SLOW_RECEIVER_PANIC, &[]).unwrap();
            panic!("The receiver/broker could not process our sent llmp messages in time. Either we're sending too many messages too fast, the broker got stuck, or it crashed. Giving up.");
        }

        // Remove all maps that the broker already mapped, move them to our unused pages cache
        self.out_shmems.reserve(unmap_until_excl);
        for _ in 0..unmap_until_excl {
            let mut map = self.out_shmems.remove(0);

            let page = shmem2page_mut(&mut map.shmem);
            assert!(
                (*page).magic == PAGE_INITIALIZED_MAGIC,
                "LLMP: Tried to free uninitialized shared map at addr {:#}!",
                page as usize
            );
            (*page).magic = PAGE_DEINITIALIZED_MAGIC;

            #[cfg(feature = "llmp_debug")]
            log::debug!("Moving unused map to cache: {map:?} {:x?}", map.page());
            self.unused_shmem_cache
                .insert(self.unused_shmem_cache.len(), map);
        }
    }

    /// Intern: Special allocation function for `EOP` messages (and nothing else!)
    /// The normal alloc will fail if there is not enough space for `buf_len_padded + EOP`
    /// So if [`alloc_next`] fails, create new page if necessary, use this function,
    /// place `EOP`, commit `EOP`, reset, alloc again on the new space.
    unsafe fn alloc_eop(&mut self) -> Result<*mut LlmpMsg, Error> {
        let map = self.out_shmems.last_mut().unwrap();
        let page = map.page_mut();
        let last_msg = self.last_msg_sent;
        assert!((*page).size_used + EOP_MSG_SIZE <= (*page).size_total,
                "PROGRAM ABORT : BUG: EOP does not fit in page! page {page:?}, size_current {:?}, size_total {:?}",
                ptr::addr_of!((*page).size_used), ptr::addr_of!((*page).size_total));

        let ret: *mut LlmpMsg = if last_msg.is_null() {
            (*page).messages.as_mut_ptr()
        } else {
            llmp_next_msg_ptr_checked(map, last_msg, EOP_MSG_SIZE)?
        };
        assert!(
            (*ret).tag != LLMP_TAG_UNINITIALIZED,
            "Did not call send() on last message!"
        );

        (*ret).buf_len = size_of::<LlmpPayloadSharedMapInfo>() as u64;

        // We don't need to pad the EOP message: it'll always be the last in this page.
        (*ret).buf_len_padded = (*ret).buf_len;
        (*ret).message_id = if last_msg.is_null() {
            MessageId(1)
        } else {
            MessageId((*last_msg).message_id.0 + 1)
        };
        (*ret).tag = LLMP_TAG_END_OF_PAGE;
        (*page).size_used += EOP_MSG_SIZE;
        Ok(ret)
    }

    /// Intern: Will return a ptr to the next msg buf, or None if map is full.
    /// Never call [`alloc_next`] without either sending or cancelling the last allocated message for this page!
    /// There can only ever be up to one message allocated per page at each given time.
    unsafe fn alloc_next_if_space(&mut self, buf_len: usize) -> Option<*mut LlmpMsg> {
        let map = self.out_shmems.last_mut().unwrap();
        let page = map.page_mut();
        let last_msg = self.last_msg_sent;

        assert!(
            !self.has_unsent_message,
            "Called alloc without calling send inbetween"
        );

        #[cfg(feature = "llmp_debug")]
        log::info!(
            "Allocating {} bytes on page {:?} / map {:?} (last msg: {:?})",
            buf_len,
            page,
            &map.shmem.id().as_str(),
            last_msg
        );

        let msg_start = (*page).messages.as_mut_ptr() as usize + (*page).size_used;

        // Make sure the end of our msg is aligned.
        let buf_len_padded = llmp_align(msg_start + buf_len + size_of::<LlmpMsg>())
            - msg_start
            - size_of::<LlmpMsg>();

        #[cfg(feature = "llmp_debug")]
        log::trace!(
            "{page:?} {:?} size_used={:x} buf_len_padded={:x} EOP_MSG_SIZE={:x} size_total={}",
            &(*page),
            (*page).size_used,
            buf_len_padded,
            EOP_MSG_SIZE,
            (*page).size_total
        );

        // We need enough space for the current page size_used + payload + padding
        if (*page).size_used + size_of::<LlmpMsg>() + buf_len_padded + EOP_MSG_SIZE
            > (*page).size_total
        {
            #[cfg(feature = "llmp_debug")]
            log::info!("LLMP: Page full.");

            /* We're full. */
            return None;
        }

        let ret = msg_start as *mut LlmpMsg;

        /* We need to start with 1 for ids, as current message id is initialized
         * with 0... */
        (*ret).message_id = if last_msg.is_null() {
            MessageId(1)
        } else if (*page).current_msg_id.load(Ordering::Relaxed) == (*last_msg).message_id.0 {
            MessageId((*last_msg).message_id.0 + 1)
        } else {
            /* Oops, wrong usage! */
            panic!("BUG: The current message never got committed using send! (page->current_msg_id {:?}, last_msg->message_id: {:?})", ptr::addr_of!((*page).current_msg_id), (*last_msg).message_id);
        };

        (*ret).buf_len = buf_len as u64;
        (*ret).buf_len_padded = buf_len_padded as u64;
        (*page).size_used += size_of::<LlmpMsg>() + buf_len_padded;

        (*_llmp_next_msg_ptr(ret)).tag = LLMP_TAG_UNSET;
        (*ret).tag = LLMP_TAG_UNINITIALIZED;

        // For future allocs, keep track of the maximum (aligned) alloc size we used
        (*page).max_alloc_size = max(
            (*page).max_alloc_size,
            size_of::<LlmpMsg>() + buf_len_padded,
        );

        self.has_unsent_message = true;

        Some(ret)
    }

    /// Commit the message last allocated by [`alloc_next`] to the queue.
    /// After commiting, the msg shall no longer be altered!
    /// It will be read by the consuming threads (`broker->clients` or `client->broker`)
    /// If `overwrite_client_id` is `false`, the message's `sender` won't be touched (for broker forwarding)
    #[inline(never)] // Not inlined to make cpu-level reodering (hopefully?) improbable
    unsafe fn send(&mut self, msg: *mut LlmpMsg, overwrite_client_id: bool) -> Result<(), Error> {
        // log::info!("Sending msg {:?}", msg);

        assert!(self.last_msg_sent != msg, "Message sent twice!");
        assert!(
            (*msg).tag != LLMP_TAG_UNSET,
            "No tag set on message with id {:?}",
            (*msg).message_id
        );
        // A client gets the sender id assigned to by the broker during the initial handshake.
        if overwrite_client_id {
            (*msg).sender = self.id;
        }
        let page = self.out_shmems.last_mut().unwrap().page_mut();
        if msg.is_null() || !llmp_msg_in_page(page, msg) {
            return Err(Error::unknown(format!(
                "Llmp Message {msg:?} is null or not in current page"
            )));
        }

        (*msg).message_id.0 = (*page).current_msg_id.load(Ordering::Relaxed) + 1;

        // Make sure all things have been written to the page, and commit the message to the page
        (*page)
            .current_msg_id
            .store((*msg).message_id.0, Ordering::Release);

        self.last_msg_sent = msg;
        self.has_unsent_message = false;
        Ok(())
    }

    /// Grab an unused `LlmpSharedMap` from `unused_shmem_cache` or allocate a new map,
    /// if no suitable maps could be found.
    unsafe fn new_or_unused_shmem(
        &mut self,
        sender_id: ClientId,
        next_min_shmem_size: usize,
    ) -> Result<LlmpSharedMap<<SP>::ShMem>, Error> {
        // Find a shared map that has been released to reuse, from which all receivers left / finished reading.
        let cached_shmem = self
            .unused_shmem_cache
            .iter()
            .position(|cached_shmem| {
                let page = &(*shmem2page(&cached_shmem.shmem));
                let receivers_joined_count = page.receivers_joined_count.load(Ordering::Relaxed);
                debug_assert_ne!(receivers_joined_count, 0);
                let receivers_left_count = page.receivers_left_count.load(Ordering::Relaxed);
                debug_assert!(receivers_joined_count >= receivers_left_count);

                let ret = receivers_joined_count == receivers_left_count;

                // For proper refcounts, double check that nobody joined in the meantime.
                debug_assert_eq!(
                    receivers_joined_count,
                    page.receivers_joined_count.load(Ordering::Relaxed),
                    "Oops, some receiver joined while re-using the page!"
                );

                ret
            })
            .map(|e| self.unused_shmem_cache.remove(e));

        if let Some(mut cached_shmem) = cached_shmem {
            // We got cached shmems laying around, hand it out, if they are large enough.
            if cached_shmem.shmem.len() < next_min_shmem_size {
                // This map is too small, we will never need it again (llmp allocation sizes always increase). Drop it, then call this function again..
                #[cfg(feature = "llmp_debug")]
                log::info!("Dropping too small shmem {cached_shmem:?}");
                drop(cached_shmem);
                self.new_or_unused_shmem(sender_id, next_min_shmem_size)
            } else {
                #[cfg(feature = "llmp_debug")]
                log::info!("Returning cached shmem {cached_shmem:?}");
                unsafe {
                    llmp_page_init(&mut cached_shmem.shmem, sender_id, false);
                }
                Ok(cached_shmem)
            }
        } else {
            // No cached maps that fit our need, let's allocate a new one.
            Ok(LlmpSharedMap::new(
                sender_id,
                self.shmem_provider.new_shmem(next_min_shmem_size)?,
            ))
        }
    }

    /// listener about it using a EOP message.
    unsafe fn handle_out_eop(&mut self) -> Result<(), Error> {
        #[cfg(all(feature = "llmp_debug", feature = "std"))]
        {
            #[cfg(debug_assertions)]
            let bt = Backtrace::new();
            #[cfg(not(debug_assertions))]
            let bt = "<n/a (release)>";
            let shm = self.out_shmems.last().unwrap();
            log::info!(
                "LLMP_DEBUG: End of page reached for map {} with len {}, sending EOP, bt: {:?}",
                shm.shmem.id(),
                shm.shmem.len(),
                bt
            );
        }

        // If we want to get red if old pages, (client to broker), do that now
        if !self.keep_pages_forever {
            #[cfg(feature = "llmp_debug")]
            log::debug!("LLMP DEBUG: pruning old pages");
            self.prune_old_pages();
        }

        let old_map = self.out_shmems.last_mut().unwrap().page_mut();

        let next_min_shmem_size = next_shmem_size((*old_map).max_alloc_size);

        #[cfg(feature = "llmp_debug")]
        log::info!("Next min ShMem Size {next_min_shmem_size}",);

        // Get a new shared page, or reuse an old one, if available.
        let mut new_map_shmem =
            self.new_or_unused_shmem((*old_map).sender_id, next_min_shmem_size)?;

        let new_map = new_map_shmem.page_mut();

        #[cfg(feature = "llmp_debug")]
        log::info!("got new map at: {new_map:?}");

        // New maps always start with 0 as message id -> No messages yet.
        (*new_map).current_msg_id.store(0, Ordering::Release);

        #[cfg(feature = "llmp_debug")]
        log::info!("Setting max alloc size: {:?}", (*old_map).max_alloc_size);

        // Allocations may never shrink:
        // keep track of the max message size we allocated across maps.
        (*new_map).max_alloc_size = (*old_map).max_alloc_size;

        /* On the old map, place a last message linking to the new map for the clients
         * to consume */
        let out = self.alloc_eop()?;

        #[allow(clippy::cast_ptr_alignment)]
        let end_of_page_msg = (*out).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;
        (*end_of_page_msg).map_size = new_map_shmem.shmem.len();
        (*end_of_page_msg).shm_str = *new_map_shmem.shmem.id().as_array();

        /* Send the last msg (the EOP message) on the old buf */
        self.send(out, true)?;

        // Set the new page as current page.
        self.out_shmems.push(new_map_shmem);
        // We never sent a msg on the new buf */
        self.last_msg_sent = ptr::null_mut();

        Ok(())
    }

    /// Allocates the next space on this sender page
    pub fn alloc_next(&mut self, buf_len: usize) -> Result<*mut LlmpMsg, Error> {
        if let Some(msg) = unsafe { self.alloc_next_if_space(buf_len) } {
            return Ok(msg);
        };

        /* no more space left! We'll have to start a new page */
        unsafe {
            self.handle_out_eop()?;
        }

        #[cfg(feature = "llmp_debug")]
        log::debug!("Handled out eop");

        match unsafe { self.alloc_next_if_space(buf_len) } {
            Some(msg) => Ok(msg),
            None => Err(Error::unknown(format!(
                "Error allocating {buf_len} bytes in shmap"
            ))),
        }
    }

    /// Cancel send of the next message, this allows us to allocate a new message without sending this one.
    /// # Safety
    /// They msg pointer may no longer be used after `cancel_send`
    pub unsafe fn cancel_send(&mut self, msg: *mut LlmpMsg) {
        /* DBG("Client %d cancels send of msg at %p with tag 0x%X and size %ld", client->id, msg, msg->tag,
         * msg->buf_len_padded); */
        let page = self.out_shmems.last_mut().unwrap().page_mut();
        (*msg).tag = LLMP_TAG_UNSET;
        (*page).size_used -= (*msg).buf_len_padded as usize + size_of::<LlmpMsg>();
    }

    /// Shrinks the allocated [`LlmpMsg`] to a given size.
    ///
    /// # Safety
    /// The msg pointer will be dereferenced, if it's not `null`.
    pub unsafe fn shrink_alloced(
        &mut self,
        msg: *mut LlmpMsg,
        shrinked_len: usize,
    ) -> Result<(), Error> {
        if msg.is_null() {
            return Err(Error::illegal_argument("Null msg passed to shrink_alloced"));
        } else if !self.has_unsent_message {
            return Err(Error::illegal_state(
                "Called shrink_alloced, but the msg was not unsent",
            ));
        }

        let old_len_padded = (*msg).buf_len_padded;

        let msg_start = msg as usize;
        // Make sure the end of our msg is aligned.
        let buf_len_padded = llmp_align(msg_start + shrinked_len + size_of::<LlmpMsg>())
            - msg_start
            - size_of::<LlmpMsg>();

        if buf_len_padded > old_len_padded.try_into().unwrap() {
            return Err(Error::illegal_argument(format!("Cannot shrink msg of size {} (paded: {old_len_padded}) to requested larger size of {shrinked_len} (padded: {buf_len_padded})!", (*msg).buf_len)));
        }

        (*msg).buf_len = shrinked_len as u64;
        (*msg).buf_len_padded = buf_len_padded as u64;

        let page = self.out_shmems.last_mut().unwrap().page_mut();

        // Doing this step by step will catch underflows in debug builds :)
        (*page).size_used -= old_len_padded as usize;
        (*page).size_used += buf_len_padded;

        (*_llmp_next_msg_ptr(msg)).tag = LLMP_TAG_UNSET;

        Ok(())
    }

    /// Allocates a message of the given size, tags it, and sends it off.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        // Make sure we don't reuse already allocated tags
        if tag == LLMP_TAG_NEW_SHM_CLIENT
            || tag == LLMP_TAG_END_OF_PAGE
            || tag == LLMP_TAG_UNINITIALIZED
            || tag == LLMP_TAG_UNSET
        {
            return Err(Error::unknown(format!(
                "Reserved tag supplied to send_buf ({tag:?})"
            )));
        }

        unsafe {
            let msg = self.alloc_next(buf.len())?;
            (*msg).tag = tag;
            (*msg).flags = LLMP_FLAG_INITIALIZED;
            buf.as_ptr()
                .copy_to_nonoverlapping((*msg).buf.as_mut_ptr(), buf.len());
            self.send(msg, true)
        }
    }

    /// Send a `buf` with the given `flags`.
    pub fn send_buf_with_flags(&mut self, tag: Tag, flags: Flags, buf: &[u8]) -> Result<(), Error> {
        // Make sure we don't reuse already allocated tags
        if tag == LLMP_TAG_NEW_SHM_CLIENT
            || tag == LLMP_TAG_END_OF_PAGE
            || tag == LLMP_TAG_UNINITIALIZED
            || tag == LLMP_TAG_UNSET
        {
            return Err(Error::unknown(format!(
                "Reserved tag supplied to send_buf ({tag:?})"
            )));
        }

        unsafe {
            let msg = self.alloc_next(buf.len())?;
            (*msg).tag = tag;
            (*msg).flags = flags;
            buf.as_ptr()
                .copy_to_nonoverlapping((*msg).buf.as_mut_ptr(), buf.len());
            self.send(msg, true)
        }
    }

    /// Describe this [`LlmpClient`] in a way that it can be restored later, using [`Self::on_existing_from_description`].
    pub fn describe(&self) -> Result<LlmpDescription, Error> {
        let map = self.out_shmems.last().unwrap();
        let last_message_offset = if self.last_msg_sent.is_null() {
            None
        } else {
            Some(unsafe { map.msg_to_offset(self.last_msg_sent) }?)
        };
        Ok(LlmpDescription {
            shmem: map.shmem.description(),
            last_message_offset,
        })
    }

    /// Create this client on an existing map from the given description.
    /// Acquired with [`self.describe`].
    pub fn on_existing_from_description(
        mut shmem_provider: SP,
        description: &LlmpDescription,
    ) -> Result<Self, Error> {
        Self::on_existing_shmem(
            shmem_provider.clone(),
            shmem_provider.shmem_from_description(description.shmem)?,
            description.last_message_offset,
        )
    }

    /// Send information that this client is exiting.
    /// The other side may free up all allocated memory.
    /// We are no longer allowed to send anything afterwards.
    pub fn send_exiting(&mut self) -> Result<(), Error> {
        self.send_buf(LLMP_TAG_EXITING, &[])
    }
}

/// Receiving end on a (unidirectional) sharedmap channel
#[derive(Debug)]
pub struct LlmpReceiver<SP>
where
    SP: ShMemProvider,
{
    /// Client Id of this receiver
    id: ClientId,
    /// Pointer to the last message received
    last_msg_recvd: *const LlmpMsg,
    /// Time we received the last message from this receiver
    #[cfg(feature = "std")]
    last_msg_time: Duration,
    /// The shmem provider
    shmem_provider: SP,
    /// current page. After EOP, this gets replaced with the new one
    current_recv_shmem: LlmpSharedMap<SP::ShMem>,
    /// Caches the highest msg id we've seen so far
    highest_msg_id: MessageId,
}

/// Receiving end of an llmp channel
impl<SP> LlmpReceiver<SP>
where
    SP: ShMemProvider,
{
    /// Reattach to a vacant `recv_shmem`, to with a previous sender stored the information in an env before.
    #[cfg(feature = "std")]
    pub fn on_existing_from_env(mut shmem_provider: SP, env_name: &str) -> Result<Self, Error> {
        Self::on_existing_shmem(
            shmem_provider.clone(),
            shmem_provider.existing_from_env(env_name)?,
            msg_offset_from_env(env_name)?,
        )
    }

    /// Store the info to this receiver to env.
    /// A new client can reattach to it using [`LlmpReceiver::on_existing_from_env()`]
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) -> Result<(), Error> {
        let current_out_shmem = &self.current_recv_shmem;
        current_out_shmem.shmem.write_to_env(env_name)?;
        unsafe { current_out_shmem.msg_to_env(self.last_msg_recvd, env_name) }
    }

    /// Create a Receiver, reattaching to an existing sender map.
    /// It is essential, that the sender (or someone else) keeps a pointer to the `sender_shmem`
    /// else reattach will get a new, empty page, from the OS, or fail.
    pub fn on_existing_shmem(
        shmem_provider: SP,
        current_sender_shmem: SP::ShMem,
        last_msg_recvd_offset: Option<u64>,
    ) -> Result<Self, Error> {
        let mut current_recv_shmem = LlmpSharedMap::existing(current_sender_shmem);
        let last_msg_recvd = match last_msg_recvd_offset {
            Some(offset) => current_recv_shmem.msg_from_offset(offset)?,
            None => ptr::null_mut(),
        };

        Ok(Self {
            id: ClientId(0),
            current_recv_shmem,
            last_msg_recvd,
            shmem_provider,
            highest_msg_id: MessageId(0),
            // We don't know the last received time, just assume the current time.
            #[cfg(feature = "std")]
            last_msg_time: current_time(),
        })
    }

    // Never inline, to not get some strange effects
    /// Read next message.
    /// Returns a pointer to the [`LlmpMsg`], `None` of no message exists, or an [`Error`].
    ///
    /// Will *not* update `self.last_msg_time`.
    #[inline(never)]
    unsafe fn recv(&mut self) -> Result<Option<*mut LlmpMsg>, Error> {
        /* DBG("recv %p %p\n", page, last_msg); */
        let page = self.current_recv_shmem.page_mut();
        let last_msg = self.last_msg_recvd;

        let (current_msg_id, loaded) =
            if !last_msg.is_null() && self.highest_msg_id > (*last_msg).message_id {
                // read the msg_id from cache
                (self.highest_msg_id, false)
            } else {
                // read the msg_id from shared map
                let current_msg_id = (*page).current_msg_id.load(Ordering::Relaxed);
                self.highest_msg_id = MessageId(current_msg_id);
                (MessageId(current_msg_id), true)
            };

        // Read the message from the page
        let ret = if current_msg_id.0 == 0 {
            /* No messages yet */
            None
        } else if last_msg.is_null() {
            /* We never read a message from this queue. Return first. */
            fence(Ordering::Acquire);
            Some((*page).messages.as_mut_ptr())
        } else if (*last_msg).message_id == current_msg_id {
            /* Oops! No new message! */
            None
        } else {
            if loaded {
                // we read a higher id from this page, fetch.
                fence(Ordering::Acquire);
            }
            // We don't know how big the msg wants to be, assert at least the header has space.
            Some(llmp_next_msg_ptr_checked(
                &mut self.current_recv_shmem,
                last_msg,
                size_of::<LlmpMsg>(),
            )?)
        };

        // Let's see what we got.
        if let Some(msg) = ret {
            if !(*msg).in_shmem(&mut self.current_recv_shmem) {
                return Err(Error::illegal_state("Unexpected message in map (out of map bounds) - buggy client or tampered shared map detected!"));
            }
            // Handle special, LLMP internal, messages.
            match (*msg).tag {
                LLMP_TAG_UNSET => panic!(
                    "BUG: Read unallocated msg (tag was {:?} - msg header: {:?}",
                    LLMP_TAG_UNSET,
                    &(*msg)
                ),
                LLMP_TAG_EXITING => {
                    // The other side is done.
                    assert_eq!((*msg).buf_len, 0);
                    return Err(Error::shutting_down());
                }
                LLMP_TAG_END_OF_PAGE => {
                    log::debug!("Received end of page, allocating next");
                    // Handle end of page
                    assert!(
                        (*msg).buf_len >= size_of::<LlmpPayloadSharedMapInfo>() as u64,
                        "Illegal message length for EOP (is {}/{}, expected {})",
                        (*msg).buf_len,
                        (*msg).buf_len_padded,
                        size_of::<LlmpPayloadSharedMapInfo>()
                    );

                    #[allow(clippy::cast_ptr_alignment)]
                    let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;

                    /* The pageinfo points to the map we're about to unmap.
                    Copy the contents first to be safe (probably fine in rust either way). */
                    let pageinfo_cpy = *pageinfo;

                    // Set last msg we received to null (as the map may no longer exist)
                    self.last_msg_recvd = ptr::null();
                    self.highest_msg_id = MessageId(0);

                    // Mark the old page save to remap.
                    (*page).receiver_left();

                    // Map the new page. The old one should be unmapped by Drop
                    self.current_recv_shmem =
                        LlmpSharedMap::existing(self.shmem_provider.shmem_from_id_and_size(
                            ShMemId::from_array(&pageinfo_cpy.shm_str),
                            pageinfo_cpy.map_size,
                        )?);
                    let new_page = self.current_recv_shmem.page_mut();

                    // Mark the old page as save to remap (it's mapped by us, the receiver, now)
                    (*new_page).receiver_joined();

                    #[cfg(feature = "llmp_debug")]
                    log::info!(
                        "LLMP_DEBUG: Got a new recv map {} with len {:?}",
                        self.current_recv_shmem.shmem.id(),
                        self.current_recv_shmem.shmem.len()
                    );
                    // After we mapped the new page, return the next message, if available
                    return self.recv();
                }
                _ => (),
            }

            // Store the last msg for next time
            self.last_msg_recvd = msg;
        };
        Ok(ret)
    }

    /// Blocks/spins until the next message gets posted to the page,
    /// then returns that message.
    /// # Safety
    /// Returns a raw ptr, on the recv map. Should be safe in general
    pub unsafe fn recv_blocking(&mut self) -> Result<*mut LlmpMsg, Error> {
        let mut current_msg_id = MessageId(0);
        let page = self.current_recv_shmem.page_mut();
        let last_msg = self.last_msg_recvd;
        if !last_msg.is_null() {
            assert!(
                (*last_msg).tag != LLMP_TAG_END_OF_PAGE || llmp_msg_in_page(page, last_msg),
                "BUG: full page passed to await_message_blocking or reset failed"
            );

            current_msg_id = (*last_msg).message_id;
        }
        loop {
            if (*page).current_msg_id.load(Ordering::Relaxed) != current_msg_id.0 {
                return match self.recv()? {
                    Some(msg) => Ok(msg),
                    None => panic!("BUG: blocking llmp message should never be NULL"),
                };
            }
            hint::spin_loop();
        }
    }

    /// Returns the next message, tag, buf, if available, else None
    #[allow(clippy::type_complexity)]
    #[inline]
    pub fn recv_buf(&mut self) -> Result<Option<(ClientId, Tag, &[u8])>, Error> {
        if let Some((sender, tag, _flags, buf)) = self.recv_buf_with_flags()? {
            Ok(Some((sender, tag, buf)))
        } else {
            Ok(None)
        }
    }

    /// Receive the buffer, also reading the LLMP internal message flags
    #[allow(clippy::type_complexity)]
    #[inline]
    pub fn recv_buf_with_flags(&mut self) -> Result<Option<(ClientId, Tag, Flags, &[u8])>, Error> {
        unsafe {
            Ok(match self.recv()? {
                Some(msg) => Some((
                    (*msg).sender,
                    (*msg).tag,
                    (*msg).flags,
                    (*msg).try_as_slice(&mut self.current_recv_shmem)?,
                )),
                None => None,
            })
        }
    }

    /// Returns the next sender, tag, buf, looping until it becomes available
    #[inline]
    pub fn recv_buf_blocking(&mut self) -> Result<(ClientId, Tag, &[u8]), Error> {
        unsafe {
            let msg = self.recv_blocking()?;
            Ok((
                (*msg).sender,
                (*msg).tag,
                (*msg).try_as_slice(&mut self.current_recv_shmem)?,
            ))
        }
    }

    /// Describe this client in a way, that it can be restored later with [`Self::on_existing_from_description`]
    pub fn describe(&self) -> Result<LlmpDescription, Error> {
        let map = &self.current_recv_shmem;
        let last_message_offset = if self.last_msg_recvd.is_null() {
            None
        } else {
            Some(unsafe { map.msg_to_offset(self.last_msg_recvd) }?)
        };
        Ok(LlmpDescription {
            shmem: map.shmem.description(),
            last_message_offset,
        })
    }

    /// Create this client on an existing map from the given description. acquired with `self.describe`
    pub fn on_existing_from_description(
        mut shmem_provider: SP,
        description: &LlmpDescription,
    ) -> Result<Self, Error> {
        Self::on_existing_shmem(
            shmem_provider.clone(),
            shmem_provider.shmem_from_description(description.shmem)?,
            description.last_message_offset,
        )
    }
}

/// A page wrapper
#[derive(Clone, Debug)]
pub struct LlmpSharedMap<SHM>
where
    SHM: ShMem,
{
    /// Shmem containg the actual (unsafe) page,
    /// shared between one `LlmpSender` and one `LlmpReceiver`
    shmem: SHM,
}

// TODO: May be obsolete
/// The page struct, placed on a shared mem instance.
/// A thin wrapper around a [`ShMem`] implementation, with special [`crate::llmp`] funcs
impl<SHM> LlmpSharedMap<SHM>
where
    SHM: ShMem,
{
    /// Creates a new page, initializing the passed shared mem struct
    pub fn new(sender: ClientId, mut new_shmem: SHM) -> Self {
        #[cfg(feature = "llmp_debug")]
        log::info!(
            "LLMP_DEBUG: Initializing map on {} with size {}",
            new_shmem.id(),
            new_shmem.len()
        );

        unsafe {
            llmp_page_init(&mut new_shmem, sender, false);
        }
        Self { shmem: new_shmem }
    }

    /// Maps and wraps an existing
    pub fn existing(existing_shmem: SHM) -> Self {
        #[cfg(feature = "llmp_debug")]
        //{
        //#[cfg(debug_assertions)]
        //let bt = Backtrace::new();
        //#[cfg(not(debug_assertions))]
        //let bt = "<n/a (release)>";
        log::info!(
            "LLMP_DEBUG: Using existing map {} with size {}",
            existing_shmem.id(),
            existing_shmem.len(),
            //bt
        );
        //}

        let ret = Self {
            shmem: existing_shmem,
        };
        unsafe {
            assert!(
                (*ret.page()).magic == PAGE_INITIALIZED_MAGIC,
                "Map was not priviously initialized at {:?}",
                &ret.shmem
            );
            #[cfg(feature = "llmp_debug")]
            log::info!("PAGE: {:?}", &(*ret.page()));
        }
        ret
    }

    /// Marks the containing page as `safe_to_unmap`.
    /// This indicates, that the page may safely be unmapped by the sender.
    pub fn mark_safe_to_unmap(&mut self) {
        unsafe {
            (*self.page_mut()).receiver_joined();
        }
    }

    /// Get the unsafe ptr to this page, situated on the shared map
    /// # Safety
    /// The unsafe page pointer is obviously unsafe.
    pub unsafe fn page_mut(&mut self) -> *mut LlmpPage {
        shmem2page_mut(&mut self.shmem)
    }

    /// Get the unsafe ptr to this page, situated on the shared map
    /// # Safety
    /// The unsafe page pointer is obviously unsafe.
    pub unsafe fn page(&self) -> *const LlmpPage {
        shmem2page(&self.shmem)
    }

    /// Gets the offset of a message on this here page.
    /// Will return [`crate::Error::illegal_argument`] error if msg is not on page.
    ///
    /// # Safety
    /// This dereferences msg, make sure to pass a proper pointer to it.
    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn msg_to_offset(&self, msg: *const LlmpMsg) -> Result<u64, Error> {
        let page = self.page();
        if llmp_msg_in_page(page, msg) {
            // Cast both sides to u8 arrays, get the offset, then cast the return isize to u64
            Ok((msg as *const u8).offset_from((*page).messages.as_ptr() as *const u8) as u64)
        } else {
            Err(Error::illegal_argument(format!(
                "Message (0x{:X}) not in page (0x{:X})",
                page as u64, msg as u64
            )))
        }
    }

    /// Retrieve the stored msg from `env_name` + `_OFFSET`.
    /// It will restore the stored offset by `env_name` and return the message.
    #[cfg(feature = "std")]
    pub fn msg_from_env(&mut self, map_env_name: &str) -> Result<*mut LlmpMsg, Error> {
        match msg_offset_from_env(map_env_name)? {
            Some(offset) => self.msg_from_offset(offset),
            None => Ok(ptr::null_mut()),
        }
    }

    /// Store this msg offset to `env_name` + `_OFFSET` env variable.
    /// It can be restored using [`LlmpSharedMap::msg_from_env()`] with the same `env_name` later.
    ///
    /// # Safety
    /// This function will dereference the msg ptr, make sure it's valid.
    #[cfg(feature = "std")]
    pub unsafe fn msg_to_env(&self, msg: *const LlmpMsg, map_env_name: &str) -> Result<(), Error> {
        if msg.is_null() {
            env::set_var(format!("{map_env_name}_OFFSET"), _NULL_ENV_STR);
        } else {
            env::set_var(
                format!("{map_env_name}_OFFSET"),
                format!("{}", self.msg_to_offset(msg)?),
            );
        }
        Ok(())
    }

    /// Gets this message from this page, at the indicated offset.
    /// Will return [`crate::Error::illegal_argument`] error if the offset is out of bounds.
    #[allow(clippy::cast_ptr_alignment)]
    pub fn msg_from_offset(&mut self, offset: u64) -> Result<*mut LlmpMsg, Error> {
        let offset = offset as usize;

        let page = unsafe { self.page_mut() };
        let page_size = self.shmem.as_slice().len() - size_of::<LlmpPage>();
        if offset > page_size {
            Err(Error::illegal_argument(format!(
                "Msg offset out of bounds (size: {page_size}, requested offset: {offset})"
            )))
        } else {
            unsafe { Ok(((*page).messages.as_mut_ptr() as *mut u8).add(offset) as *mut LlmpMsg) }
        }
    }
}

/// The broker (node 0)
#[derive(Debug)]
pub struct LlmpBroker<SP>
where
    SP: ShMemProvider + 'static,
{
    /// Broadcast map from broker to all clients
    llmp_out: LlmpSender<SP>,
    /// Users of Llmp can add message handlers in the broker.
    /// This allows us to intercept messages right in the broker.
    /// This keeps the out map clean.
    /// The backing values of `llmp_clients` [`ClientId`]s will always be sorted (but not gapless)
    /// Make sure to always increase `num_clients_total` when pushing a new [`LlmpReceiver`] to  `llmp_clients`!
    llmp_clients: Vec<LlmpReceiver<SP>>,
    /// The own listeners we spawned via `launch_listener` or `crate_attach_to_tcp`.
    /// Listeners will be ignored for `exit_cleanly_after` and they are never considered to have timed out.
    listeners: Vec<ClientId>,
    /// The total amount of clients we had, historically, including those that disconnected, and our listeners.
    num_clients_total: usize,
    /// The amount of total clients that should have connected and (and disconnected)
    /// after which the broker loop should quit gracefully.
    pub exit_cleanly_after: Option<NonZeroUsize>,
    /// Clients that should be removed soon, (offset into `llmp_clients`)
    clients_to_remove: Vec<usize>,
    /// The `ShMemProvider` to use
    shmem_provider: SP,
    #[cfg(feature = "std")]
    /// The timeout after which a client will be considered stale, and removed.
    client_timeout: Duration,
}

/// A signal handler for the [`LlmpBroker`].
/// On unix, it handles signals
/// On Windows - control signals (e.g., CTRL+C)
#[cfg(any(unix, all(windows, feature = "std")))]
#[derive(Debug, Clone)]
pub struct LlmpShutdownSignalHandler {
    shutting_down: bool,
}

#[cfg(unix)]
impl Handler for LlmpShutdownSignalHandler {
    fn handle(
        &mut self,
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
    ) {
        unsafe {
            ptr::write_volatile(ptr::addr_of_mut!(self.shutting_down), true);
        }
    }

    fn signals(&self) -> Vec<Signal> {
        vec![Signal::SigTerm, Signal::SigInterrupt, Signal::SigQuit]
    }
}

#[cfg(all(windows, feature = "std"))]
impl CtrlHandler for LlmpShutdownSignalHandler {
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn handle(&mut self, ctrl_type: u32) -> bool {
        log::info!("LLMP: Received shutdown signal, ctrl_type {:?}", ctrl_type);
        unsafe {
            ptr::write_volatile(&mut self.shutting_down, true);
        }
        true
    }
}

/// The broker forwards all messages to its own bus-like broadcast map.
/// It may intercept messages passing through.
impl<SP> LlmpBroker<SP>
where
    SP: ShMemProvider + 'static,
{
    /// Create and initialize a new [`LlmpBroker`]
    pub fn new(
        shmem_provider: SP,
        #[cfg(feature = "std")] client_timeout: Duration,
    ) -> Result<Self, Error> {
        // Broker never cleans up the pages so that new
        // clients may join at any time
        #[cfg(feature = "std")]
        {
            Self::with_keep_pages(shmem_provider, true, client_timeout)
        }

        #[cfg(not(feature = "std"))]
        {
            Self::with_keep_pages(shmem_provider, true)
        }
    }

    /// Create and initialize a new [`LlmpBroker`] telling if it has to keep pages forever
    pub fn with_keep_pages(
        mut shmem_provider: SP,
        keep_pages_forever: bool,
        #[cfg(feature = "std")] client_timeout: Duration,
    ) -> Result<Self, Error> {
        Ok(LlmpBroker {
            llmp_out: LlmpSender {
                id: ClientId(0),
                last_msg_sent: ptr::null_mut(),
                out_shmems: vec![LlmpSharedMap::new(
                    ClientId(0),
                    shmem_provider.new_shmem(next_shmem_size(0))?,
                )],
                keep_pages_forever,
                has_unsent_message: false,
                shmem_provider: shmem_provider.clone(),
                unused_shmem_cache: vec![],
            },
            llmp_clients: vec![],
            clients_to_remove: vec![],
            shmem_provider,
            listeners: vec![],
            exit_cleanly_after: None,
            num_clients_total: 0,
            #[cfg(feature = "std")]
            client_timeout,
        })
    }

    /// Gets the [`ClientId`] the next client attaching to this broker will get.
    /// In its current implememtation, the inner value of the next [`ClientId`]
    /// is equal to `self.num_clients_total`.
    /// Calling `peek_next_client_id` mutliple times (without adding a client) will yield the same value.
    #[must_use]
    #[inline]
    pub fn peek_next_client_id(&self) -> ClientId {
        ClientId(
            self.num_clients_total
                .try_into()
                .expect("More than u32::MAX clients!"),
        )
    }

    /// Create a new [`LlmpBroker`] attaching to a TCP port
    #[cfg(feature = "std")]
    pub fn create_attach_to_tcp(
        shmem_provider: SP,
        port: u16,
        client_timeout: Duration,
    ) -> Result<Self, Error> {
        Self::with_keep_pages_attach_to_tcp(shmem_provider, port, true, client_timeout)
    }

    /// Create a new [`LlmpBroker`] attaching to a TCP port and telling if it has to keep pages forever
    #[cfg(feature = "std")]
    pub fn with_keep_pages_attach_to_tcp(
        shmem_provider: SP,
        port: u16,
        keep_pages_forever: bool,
        client_timeout: Duration,
    ) -> Result<Self, Error> {
        match tcp_bind(port) {
            Ok(listener) => {
                let mut broker = LlmpBroker::with_keep_pages(
                    shmem_provider,
                    keep_pages_forever,
                    client_timeout,
                )?;
                let _listener_thread = broker.launch_listener(Listener::Tcp(listener))?;
                Ok(broker)
            }
            Err(e) => Err(e),
        }
    }

    /// Set this broker to exit after at least `count` clients attached and all client exited.
    /// Will ignore the own listener thread, if `create_attach_to_tcp`
    ///
    /// So, if the `n_client` value is `2`, the broker will not exit after client 1 connected and disconnected,
    /// but it will quit after client 2 connected and disconnected.
    pub fn set_exit_cleanly_after(&mut self, n_clients: NonZeroUsize) {
        self.exit_cleanly_after = Some(n_clients);
    }

    /// Add a client to this broker.
    /// Will set an appropriate [`ClientId`] before pushing the client to the internal vec.
    /// Will increase `num_clients_total`.
    /// The backing values of `llmp_clients` [`ClientId`]s will always be sorted (but not gapless)
    /// returns the [`ClientId`] of the new client.
    pub fn add_client(&mut self, mut client_receiver: LlmpReceiver<SP>) -> ClientId {
        let id = self.peek_next_client_id();
        client_receiver.id = id;
        self.llmp_clients.push(client_receiver);
        self.num_clients_total += 1;
        id
    }

    /// Allocate the next message on the outgoing map
    unsafe fn alloc_next(&mut self, buf_len: usize) -> Result<*mut LlmpMsg, Error> {
        self.llmp_out.alloc_next(buf_len)
    }

    /// Registers a new client for the given sharedmap str and size.
    /// Returns the id of the new client in [`broker.client_shmem`]
    pub fn register_client(&mut self, mut client_page: LlmpSharedMap<SP::ShMem>) -> ClientId {
        // Tell the client it may unmap its initial allocated shmem page now.
        // Since we now have a handle to it, it won't be umapped too early (only after we also unmap it)
        client_page.mark_safe_to_unmap();

        self.add_client(LlmpReceiver {
            id: ClientId(0), // Will be auto-filled
            current_recv_shmem: client_page,
            last_msg_recvd: ptr::null_mut(),
            shmem_provider: self.shmem_provider.clone(),
            highest_msg_id: MessageId(0),
            // We don't know the last received time, just assume the current time.
            #[cfg(feature = "std")]
            last_msg_time: current_time(),
        })
    }

    /// Connects to a broker running on another machine.
    /// This will spawn a new background thread, registered as client, that proxies all messages to a remote machine.
    /// Returns the description of the new page that still needs to be announced/added to the broker afterwards.
    #[cfg(feature = "std")]
    pub fn connect_b2b<A>(&mut self, addr: A) -> Result<(), Error>
    where
        A: ToSocketAddrs,
    {
        let mut stream = TcpStream::connect(addr)?;
        log::info!("B2B: Connected to {stream:?}");

        match recv_tcp_msg(&mut stream)?.try_into()? {
            TcpResponse::BrokerConnectHello {
                broker_shmem_description: _,
                hostname,
            } => log::info!("B2B: Connected to {hostname}"),
            _ => {
                return Err(Error::illegal_state(
                    "Unexpected response from B2B server received.".to_string(),
                ))
            }
        };

        let hostname = hostname::get()
            .unwrap_or_else(|_| "<unknown>".into())
            .to_string_lossy()
            .into();

        send_tcp_msg(&mut stream, &TcpRequest::RemoteBrokerHello { hostname })?;

        let broker_id = match recv_tcp_msg(&mut stream)?.try_into()? {
            TcpResponse::RemoteBrokerAccepted { broker_id } => {
                log::info!("B2B: Got Connection Ack, broker_id {broker_id:?}");
                broker_id
            }
            _ => {
                return Err(Error::illegal_state(
                    "Unexpected response from B2B server received.".to_string(),
                ));
            }
        };

        // TODO: use broker ids!
        log::info!("B2B: We are broker {broker_id:?}");

        // TODO: handle broker_ids properly/at all.
        let map_description = Self::b2b_thread_on(
            stream,
            self.peek_next_client_id(),
            &self
                .llmp_out
                .out_shmems
                .first()
                .unwrap()
                .shmem
                .description(),
        )?;

        let new_shmem = LlmpSharedMap::existing(
            self.shmem_provider
                .shmem_from_description(map_description)?,
        );

        {
            self.register_client(new_shmem);
        }

        Ok(())
    }

    /// For internal use: Forward the current message to the out map.
    unsafe fn forward_msg(&mut self, msg: *mut LlmpMsg) -> Result<(), Error> {
        let out: *mut LlmpMsg = self.alloc_next((*msg).buf_len_padded as usize)?;

        /* Copy over the whole message.
        If we should need zero copy, we could instead post a link to the
        original msg with the map_id and offset. */
        let actual_size = (*out).buf_len_padded;
        let complete_size = actual_size as usize + size_of::<LlmpMsg>();
        (msg as *const u8).copy_to_nonoverlapping(out as *mut u8, complete_size);
        (*out).buf_len_padded = actual_size;
        /* We need to replace the message ID with our own */
        if let Err(e) = self.llmp_out.send(out, false) {
            panic!("Error sending msg: {e:?}");
        }
        self.llmp_out.last_msg_sent = out;
        Ok(())
    }

    /// The broker walks all pages and looks for changes, then broadcasts them on
    /// its own shared page, once.
    #[inline]
    pub fn once<F>(&mut self, on_new_msg: &mut F) -> Result<bool, Error>
    where
        F: FnMut(ClientId, Tag, Flags, &[u8]) -> Result<LlmpMsgHookResult, Error>,
    {
        #[cfg(feature = "std")]
        let current_time = current_time();
        let mut new_messages = false;
        for i in 0..self.llmp_clients.len() {
            let client_id = self.llmp_clients[i].id;
            match unsafe { self.handle_new_msgs(client_id, on_new_msg) } {
                Ok(has_messages) => {
                    // See if we need to remove this client, in case no new messages got brokered, and it's not a listener
                    #[cfg(feature = "std")]
                    if !has_messages && !self.listeners.iter().any(|&x| x == client_id) {
                        let last_msg_time = self.llmp_clients[i].last_msg_time;
                        if last_msg_time < current_time
                            && current_time - last_msg_time > self.client_timeout
                        {
                            self.clients_to_remove.push(i);
                            #[cfg(feature = "llmp_debug")]
                            log::info!("Client #{:#?} timed out. Removing.", client_id);
                        }
                    }
                    new_messages = has_messages;
                }
                Err(Error::ShuttingDown) => self.clients_to_remove.push(i),
                Err(err) => return Err(err),
            }
        }

        // After brokering, remove all clients we don't want to keep.
        for i in self.clients_to_remove.iter().rev() {
            let client_id = self.llmp_clients[*i].id;
            log::info!("Client #{:#?} disconnected.", client_id);
            self.llmp_clients.remove(*i);
        }
        self.clients_to_remove.clear();
        Ok(new_messages)
    }

    /// Internal function, returns true when shuttdown is requested by a `SIGINT` signal
    #[inline]
    #[cfg(any(unix, all(windows, feature = "std")))]
    #[allow(clippy::unused_self)]
    fn is_shutting_down(&self) -> bool {
        unsafe { ptr::read_volatile(ptr::addr_of!(LLMP_SIGHANDLER_STATE.shutting_down)) }
    }

    #[cfg(any(all(unix, not(miri)), all(windows, feature = "std")))]
    fn setup_handlers() {
        #[cfg(all(unix, not(miri)))]
        if let Err(e) = unsafe { setup_signal_handler(ptr::addr_of_mut!(LLMP_SIGHANDLER_STATE)) } {
            // We can live without a proper ctrl+c signal handler - Ignore.
            log::info!("Failed to setup signal handlers: {e}");
        } else {
            log::info!("Successfully setup signal handlers");
        }

        #[cfg(all(windows, feature = "std"))]
        if let Err(e) = unsafe { setup_ctrl_handler(ptr::addr_of_mut!(LLMP_SIGHANDLER_STATE)) } {
            // We can live without a proper ctrl+c signal handler - Ignore.
            log::info!("Failed to setup control handlers: {e}");
        } else {
            log::info!(
                "{}: Broker successfully setup control handlers",
                std::process::id().to_string()
            );
        }
    }

    /// Always returns true on platforms, where no shutdown signal handlers are supported
    #[inline]
    #[cfg(not(any(unix, all(windows, feature = "std"))))]
    #[allow(clippy::unused_self)]
    fn is_shutting_down(&self) -> bool {
        false
    }

    /// Returns if any clients are currently connected.
    /// Ignores listener threads that belong to the broker,
    /// talking to other brokers via TCP, and accepting new clients over this port.
    #[inline]
    fn has_clients(&self) -> bool {
        self.llmp_clients.len() > self.listeners.len()
    }

    /// Loops until the last client quits,
    /// forwarding and handling all incoming messages from clients.
    /// Will call `on_timeout` roughly after `timeout`
    /// Panics on error.
    /// 5 millis of sleep can't hurt to keep busywait not at 100%
    #[cfg(feature = "std")]
    pub fn loop_with_timeouts<F>(
        &mut self,
        on_new_msg_or_timeout: &mut F,
        timeout: Duration,
        sleep_time: Option<Duration>,
    ) where
        F: FnMut(Option<(ClientId, Tag, Flags, &[u8])>) -> Result<LlmpMsgHookResult, Error>,
    {
        use super::current_milliseconds;

        #[cfg(any(all(unix, not(miri)), all(windows, feature = "std")))]
        Self::setup_handlers();

        let timeout = timeout.as_millis() as u64;
        let mut end_time = current_milliseconds() + timeout;

        while !self.is_shutting_down() {
            if current_milliseconds() > end_time {
                on_new_msg_or_timeout(None).expect("An error occurred in broker timeout. Exiting.");
                end_time = current_milliseconds() + timeout;
            }

            if self
                .once(&mut |client_id, tag, flags, buf| {
                    on_new_msg_or_timeout(Some((client_id, tag, flags, buf)))
                })
                .expect("An error occurred when brokering. Exiting.")
            {
                end_time = current_milliseconds() + timeout;
            }

            if let Some(exit_after_count) = self.exit_cleanly_after {
                // log::trace!(
                //     "Clients connected: {} && > {} - {} >= {}",
                //     self.has_clients(),
                //     self.num_clients_total,
                //     self.listeners.len(),
                //     exit_after_count
                // );
                if !self.has_clients()
                    && (self.num_clients_total - self.listeners.len()) >= exit_after_count.into()
                {
                    // No more clients connected, and the amount of clients we were waiting for was previously connected.
                    // exit cleanly.
                    break;
                }
            }

            #[cfg(feature = "std")]
            if let Some(time) = sleep_time {
                thread::sleep(time);
            }

            #[cfg(not(feature = "std"))]
            if let Some(time) = sleep_time {
                panic!("Cannot sleep on no_std platform (requested {time:?})");
            }
        }
        self.llmp_out
            .send_buf(LLMP_TAG_EXITING, &[])
            .expect("Error when shutting down broker: Could not send LLMP_TAG_EXITING msg.");
    }

    /// Loops unitl the last client quit,
    /// forwarding and handling all incoming messages from clients.
    /// 5 millis of sleep can't hurt to keep busywait not at 100%
    /// On std, if you need to run code even if no update got sent, use `Self::loop_with_timeout` (needs the `std` feature).
    pub fn loop_forever<F>(&mut self, on_new_msg: &mut F, sleep_time: Option<Duration>)
    where
        F: FnMut(ClientId, Tag, Flags, &[u8]) -> Result<LlmpMsgHookResult, Error>,
    {
        #[cfg(any(all(unix, not(miri)), all(windows, feature = "std")))]
        Self::setup_handlers();

        while !self.is_shutting_down() {
            self.once(on_new_msg)
                .expect("An error occurred when brokering. Exiting.");

            if let Some(exit_after_count) = self.exit_cleanly_after {
                if !self.has_clients()
                    && (self.num_clients_total - self.listeners.len()) > exit_after_count.into()
                {
                    // No more clients connected, and the amount of clients we were waiting for was previously connected.
                    // exit cleanly.
                    break;
                }
            }

            #[cfg(feature = "std")]
            if let Some(time) = sleep_time {
                thread::sleep(time);
            }

            #[cfg(not(feature = "std"))]
            if let Some(time) = sleep_time {
                panic!("Cannot sleep on no_std platform (requested {time:?})");
            }
        }
        self.llmp_out
            .send_buf(LLMP_TAG_EXITING, &[])
            .expect("Error when shutting down broker: Could not send LLMP_TAG_EXITING msg.");
    }

    /// Broadcasts the given buf to all clients
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        self.llmp_out.send_buf(tag, buf)
    }

    /// Sends a `buf` with the given `flags`.
    pub fn send_buf_with_flags(&mut self, tag: Tag, flags: Flags, buf: &[u8]) -> Result<(), Error> {
        self.llmp_out.send_buf_with_flags(tag, flags, buf)
    }

    /// Launches a thread using a tcp listener socket, on which new clients may connect to this broker.
    /// Does so on the given port.
    #[cfg(feature = "std")]
    pub fn launch_tcp_listener_on(&mut self, port: u16) -> Result<thread::JoinHandle<()>, Error> {
        let listener = tcp_bind(port)?;
        // accept connections and process them, spawning a new thread for each one
        log::info!("Server listening on port {port}");
        self.launch_listener(Listener::Tcp(listener))
    }

    /// Announces a new client on the given shared map.
    /// Called from a background thread, typically.
    /// Upon receiving this message, the broker should map the announced page and start trckang it for new messages.
    #[allow(dead_code)]
    fn announce_new_client(
        sender: &mut LlmpSender<SP>,
        shmem_description: &ShMemDescription,
    ) -> Result<(), Error> {
        unsafe {
            let msg = sender
                .alloc_next(size_of::<LlmpPayloadSharedMapInfo>())
                .expect("Could not allocate a new message in shared map.");
            (*msg).tag = LLMP_TAG_NEW_SHM_CLIENT;
            #[allow(clippy::cast_ptr_alignment)]
            let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;
            (*pageinfo).shm_str = *shmem_description.id.as_array();
            (*pageinfo).map_size = shmem_description.size;
            sender.send(msg, true)
        }
    }

    /// For broker to broker connections:
    /// Launches a proxy thread.
    /// It will read outgoing messages from the given broker map (and handle EOP by mapping a new page).
    /// This function returns the [`ShMemDescription`] the client uses to place incoming messages.
    /// The thread exits, when the remote broker disconnects.
    #[cfg(feature = "std")]
    #[allow(clippy::let_and_return, clippy::too_many_lines)]
    fn b2b_thread_on(
        mut stream: TcpStream,
        b2b_client_id: ClientId,
        broker_shmem_description: &ShMemDescription,
    ) -> Result<ShMemDescription, Error> {
        let broker_shmem_description = *broker_shmem_description;

        // A channel to get the new "client's" sharedmap id from
        let (send, recv) = channel();

        // (For now) the thread remote broker 2 broker just acts like a "normal" llmp client, except it proxies all messages to the attached socket, in both directions.
        thread::spawn(move || {
            // Crete a new ShMemProvider for this background thread
            let shmem_provider_bg = SP::new().unwrap();

            #[cfg(fature = "llmp_debug")]
            log::info!("B2b: Spawned proxy thread");

            // The background thread blocks on the incoming connection for 15 seconds (if no data is available), then checks if it should forward own messages, then blocks some more.
            stream
                .set_read_timeout(Some(_LLMP_B2B_BLOCK_TIME))
                .expect("Failed to set tcp stream timeout");

            let mut new_sender =
                match LlmpSender::new(shmem_provider_bg.clone(), b2b_client_id, false) {
                    Ok(new_sender) => new_sender,
                    Err(e) => {
                        panic!("B2B: Could not map shared map: {e}");
                    }
                };

            send.send(new_sender.out_shmems.first().unwrap().shmem.description())
                .expect("B2B: Error sending map description to channel!");

            // the receiver receives from the local broker, and forwards it to the tcp stream.
            let mut local_receiver = LlmpReceiver::on_existing_from_description(
                shmem_provider_bg,
                &LlmpDescription {
                    last_message_offset: None,
                    shmem: broker_shmem_description,
                },
            )
            .expect("Failed to map local page in broker 2 broker thread!");

            #[cfg(feature = "llmp_debug")]
            log::info!("B2B: Starting proxy loop :)");

            let peer_address = stream.peer_addr().unwrap();

            loop {
                // first, forward all data we have.
                loop {
                    match local_receiver.recv_buf_with_flags() {
                        Ok(None) => break, // no more data to forward
                        Ok(Some((client_id, tag, flags, payload))) => {
                            if client_id == b2b_client_id {
                                log::info!(
                                    "Ignored message we probably sent earlier (same id), TAG: {tag:?}"
                                );
                                continue;
                            }

                            #[cfg(feature = "llmp_debug")]
                            log::info!(
                                "Fowarding message ({} bytes) via broker2broker connection",
                                payload.len()
                            );
                            // We got a new message! Forward...
                            if let Err(e) = send_tcp_msg(
                                &mut stream,
                                &TcpRemoteNewMessage {
                                    client_id,
                                    tag,
                                    flags,
                                    payload: payload.to_vec(),
                                },
                            ) {
                                log::info!("Got error {e} while trying to forward a message to broker {peer_address}, exiting thread");
                                return;
                            }
                        }
                        Err(Error::ShuttingDown) => {
                            log::info!("Local broker is shutting down, exiting thread");
                            return;
                        }
                        Err(e) => panic!("Error reading from local page! {e}"),
                    }
                }

                // Then, see if we can receive something.
                // We set a timeout on the receive earlier.
                // This makes sure we will still forward our own stuff.
                // Forwarding happens between each recv, too, as simplification.
                // We ignore errors completely as they may be timeout, or stream closings.
                // Instead, we catch stream close when/if we next try to send.
                match recv_tcp_msg(&mut stream) {
                    Ok(val) => {
                        let msg: TcpRemoteNewMessage = val.try_into().expect(
                            "Illegal message received from broker 2 broker connection - shutting down.",
                        );

                        #[cfg(feature = "llmp_debug")]
                        log::info!(
                            "Fowarding incoming message ({} bytes) from broker2broker connection",
                            msg.payload.len()
                        );

                        // TODO: Could probably optimize this somehow to forward all queued messages between locks... oh well.
                        // Todo: somehow mangle in the other broker id? ClientId?
                        new_sender
                            .send_buf_with_flags(
                                msg.tag,
                                msg.flags | LLMP_FLAG_FROM_B2B,
                                &msg.payload,
                            )
                            .expect("B2B: Error forwarding message. Exiting.");
                    }
                    Err(e) => {
                        if let Error::OsError(e, ..) = e {
                            if e.kind() == ErrorKind::UnexpectedEof {
                                log::info!(
                                    "Broker {peer_address} seems to have disconnected, exiting"
                                );
                                return;
                            }
                        }

                        #[cfg(feature = "llmp_debug")]
                        log::info!("Received no input, timeout or closed. Looping back up :)");
                    }
                }
            }
        });

        let ret = recv.recv().map_err(|_| {
            Error::unknown("Error launching background thread for b2b communcation".to_string())
        });

        #[cfg(feature = "llmp_debug")]
        log::info!("B2B: returning from loop. Success: {}", ret.is_ok());

        ret
    }

    /// handles a single tcp request in the current context.
    #[cfg(feature = "std")]
    fn handle_tcp_request(
        mut stream: TcpStream,
        request: &TcpRequest,
        current_client_id: &mut ClientId,
        sender: &mut LlmpSender<SP>,
        broker_shmem_description: &ShMemDescription,
    ) {
        match request {
            TcpRequest::LocalClientHello { shmem_description } => {
                match Self::announce_new_client(sender, shmem_description) {
                    Ok(()) => (),
                    Err(e) => log::info!("Error forwarding client on map: {e:?}"),
                };

                if let Err(e) = send_tcp_msg(
                    &mut stream,
                    &TcpResponse::LocalClientAccepted {
                        client_id: *current_client_id,
                    },
                ) {
                    log::info!("An error occurred sending via tcp {e}");
                };
                current_client_id.0 += 1;
            }
            TcpRequest::RemoteBrokerHello { hostname } => {
                log::info!("B2B new client: {hostname}");

                // TODO: Clean up broker ids.
                if send_tcp_msg(
                    &mut stream,
                    &TcpResponse::RemoteBrokerAccepted {
                        broker_id: BrokerId(current_client_id.0),
                    },
                )
                .is_err()
                {
                    log::info!("Error accepting broker, ignoring.");
                    return;
                }

                if let Ok(shmem_description) =
                    Self::b2b_thread_on(stream, *current_client_id, broker_shmem_description)
                {
                    if Self::announce_new_client(sender, &shmem_description).is_err() {
                        log::info!("B2B: Error announcing client {shmem_description:?}");
                    };
                    current_client_id.0 += 1;
                }
            }
        };
    }

    #[cfg(feature = "std")]
    /// Launches a thread using a listener socket, on which new clients may connect to this broker
    pub fn launch_listener(&mut self, listener: Listener) -> Result<thread::JoinHandle<()>, Error> {
        // Later in the execution, after the initial map filled up,
        // the current broacast map will will point to a different map.
        // However, the original map is (as of now) never freed, new clients will start
        // to read from the initial map id.

        let client_out_shmem_mem = &self.llmp_out.out_shmems.first().unwrap().shmem;
        let broker_shmem_description = client_out_shmem_mem.description();
        let hostname = hostname::get()
            .unwrap_or_else(|_| "<unknown>".into())
            .to_string_lossy()
            .into();
        let broker_hello = TcpResponse::BrokerConnectHello {
            broker_shmem_description,
            hostname,
        };

        let llmp_tcp_id = self.peek_next_client_id();

        // Tcp out map sends messages from background thread tcp server to foreground client
        let tcp_out_shmem = LlmpSharedMap::new(
            llmp_tcp_id,
            self.shmem_provider.new_shmem(LLMP_CFG_INITIAL_MAP_SIZE)?,
        );
        let tcp_out_shmem_description = tcp_out_shmem.shmem.description();
        let listener_id = self.register_client(tcp_out_shmem);

        let ret = thread::spawn(move || {
            // Create a new ShMemProvider for this background thread.
            let mut shmem_provider_bg = SP::new().unwrap();

            let mut current_client_id = ClientId(llmp_tcp_id.0 + 1);

            let mut tcp_incoming_sender = LlmpSender {
                id: llmp_tcp_id,
                last_msg_sent: ptr::null_mut(),
                out_shmems: vec![LlmpSharedMap::existing(
                    shmem_provider_bg
                        .shmem_from_description(tcp_out_shmem_description)
                        .unwrap(),
                )],
                // drop pages to the broker, if it already read them.
                keep_pages_forever: false,
                has_unsent_message: false,
                shmem_provider: shmem_provider_bg.clone(),
                unused_shmem_cache: vec![],
            };

            loop {
                match listener.accept() {
                    ListenerStream::Tcp(mut stream, addr) => {
                        log::info!(
                            "New connection: {:?}/{:?}",
                            addr,
                            stream.peer_addr().unwrap()
                        );

                        // Send initial information, without anyone asking.
                        // This makes it a tiny bit easier to map the  broker map for new Clients.
                        match send_tcp_msg(&mut stream, &broker_hello) {
                            Ok(()) => {}
                            Err(e) => {
                                log::error!("Error sending initial hello: {e:?}");
                                continue;
                            }
                        }

                        let buf = match recv_tcp_msg(&mut stream) {
                            Ok(buf) => buf,
                            Err(e) => {
                                log::error!("Error receving from tcp: {e:?}");
                                continue;
                            }
                        };
                        let req = match buf.try_into() {
                            Ok(req) => req,
                            Err(e) => {
                                log::error!("Could not deserialize tcp message: {e:?}");
                                continue;
                            }
                        };

                        Self::handle_tcp_request(
                            stream,
                            &req,
                            &mut current_client_id,
                            &mut tcp_incoming_sender,
                            &broker_shmem_description,
                        );
                    }
                    ListenerStream::Empty() => {
                        continue;
                    }
                };
            }
        });

        self.listeners.push(listener_id);

        Ok(ret)
    }

    /// Broker broadcast to its own page for all others to read
    /// Returns `true` if new messages were broker-ed
    #[inline]
    #[allow(clippy::cast_ptr_alignment)]
    unsafe fn handle_new_msgs<F>(
        &mut self,
        client_id: ClientId,
        on_new_msg: &mut F,
    ) -> Result<bool, Error>
    where
        F: FnMut(ClientId, Tag, Flags, &[u8]) -> Result<LlmpMsgHookResult, Error>,
    {
        let mut new_messages = false;

        // TODO: We could memcpy a range of pending messages, instead of one by one.
        loop {
            let msg = {
                let pos = if (client_id.0 as usize) < self.llmp_clients.len()
                    && self.llmp_clients[client_id.0 as usize].id == client_id
                {
                    // Fast path when no client before this one was removed
                    client_id.0 as usize
                } else {
                    self.llmp_clients
                        .binary_search_by_key(&client_id, |x| x.id)
                        .expect("Fatal error, client ID {client_id} not found in llmp_clients.")
                };
                let client = &mut self.llmp_clients[pos];
                match client.recv()? {
                    None => {
                        // We're done handling this client
                        #[cfg(feature = "std")]
                        if new_messages {
                            // set the recv time
                            // We don't do that in recv() to keep calls to `current_time` to a minimum.
                            self.llmp_clients[pos].last_msg_time = current_time();
                        }
                        return Ok(new_messages);
                    }
                    Some(msg) => msg,
                }
            };
            // We got a new message
            new_messages = true;

            match (*msg).tag {
                // first, handle the special, llmp-internal messages
                LLMP_SLOW_RECEIVER_PANIC => {
                    return Err(Error::unknown(format!("The broker was too slow to handle messages of client {client_id:?} in time, so it quit. Either the client sent messages too fast, or we (the broker) got stuck!")));
                }
                LLMP_TAG_NEW_SHM_CLIENT => {
                    /* This client informs us about yet another new client
                    add it to the list! Also, no need to forward this msg. */
                    let msg_buf_len_padded = (*msg).buf_len_padded;
                    if (*msg).buf_len < size_of::<LlmpPayloadSharedMapInfo>() as u64 {
                        log::info!("Ignoring broken CLIENT_ADDED msg due to incorrect size. Expected {} but got {}",
                            msg_buf_len_padded,
                            size_of::<LlmpPayloadSharedMapInfo>()
                        );
                        #[cfg(not(feature = "std"))]
                        return Err(Error::unknown(format!("Broken CLIENT_ADDED msg with incorrect size received. Expected {} but got {}",
                            msg_buf_len_padded,
                            size_of::<LlmpPayloadSharedMapInfo>()
                        )));
                    }
                    let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;

                    match self.shmem_provider.shmem_from_id_and_size(
                        ShMemId::from_array(&(*pageinfo).shm_str),
                        (*pageinfo).map_size,
                    ) {
                        Ok(new_shmem) => {
                            let mut new_page = LlmpSharedMap::existing(new_shmem);
                            new_page.mark_safe_to_unmap();

                            self.add_client(LlmpReceiver {
                                id: ClientId(0), // will be auto-filled
                                current_recv_shmem: new_page,
                                last_msg_recvd: ptr::null_mut(),
                                shmem_provider: self.shmem_provider.clone(),
                                highest_msg_id: MessageId(0),
                                // We don't know the last received time, just assume the current time.
                                #[cfg(feature = "std")]
                                last_msg_time: current_time(),
                            });
                        }
                        Err(e) => {
                            log::info!("Error adding client! Ignoring: {e:?}");
                            #[cfg(not(feature = "std"))]
                            return Err(Error::unknown(format!(
                                "Error adding client! PANIC! {e:?}"
                            )));
                        }
                    };
                }
                // handle all other messages
                _ => {
                    // The message is not specifically for use. Let the user handle it, then forward it to the clients, if necessary.
                    let mut should_forward_msg = true;

                    let pos = if (client_id.0 as usize) < self.llmp_clients.len()
                        && self.llmp_clients[client_id.0 as usize].id == client_id
                    {
                        // Fast path when no client before this one was removed
                        client_id.0 as usize
                    } else {
                        self.llmp_clients
                            .binary_search_by_key(&client_id, |x| x.id)
                            .expect("Fatal error, client ID {client_id} not found in llmp_clients.")
                    };

                    let map = &mut self.llmp_clients[pos].current_recv_shmem;
                    let msg_buf = (*msg).try_as_slice(map)?;
                    if let LlmpMsgHookResult::Handled =
                        (on_new_msg)(client_id, (*msg).tag, (*msg).flags, msg_buf)?
                    {
                        should_forward_msg = false;
                    }
                    if should_forward_msg {
                        self.forward_msg(msg)?;
                    }
                }
            }
        }
    }
}

/// A restorable client description
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct LlmpClientDescription {
    /// Description of the sender
    sender: LlmpDescription,
    /// Description of the receiver
    receiver: LlmpDescription,
}

/// Client side of LLMP
#[derive(Debug)]
pub struct LlmpClient<SP>
where
    SP: ShMemProvider,
{
    /// Outgoing channel to the broker
    sender: LlmpSender<SP>,
    /// Incoming (broker) broadcast map
    receiver: LlmpReceiver<SP>,
}

/// `n` clients connect to a broker. They share an outgoing map with the broker,
/// and get incoming messages from the shared broker bus
impl<SP> LlmpClient<SP>
where
    SP: ShMemProvider,
{
    /// Reattach to a vacant client map.
    /// It is essential, that the broker (or someone else) kept a pointer to the `out_shmem`
    /// else reattach will get a new, empty page, from the OS, or fail
    #[allow(clippy::needless_pass_by_value)]
    pub fn on_existing_shmem(
        shmem_provider: SP,
        _current_out_shmem: SP::ShMem,
        _last_msg_sent_offset: Option<u64>,
        current_broker_shmem: SP::ShMem,
        last_msg_recvd_offset: Option<u64>,
    ) -> Result<Self, Error> {
        Ok(Self {
            receiver: LlmpReceiver::on_existing_shmem(
                shmem_provider.clone(),
                current_broker_shmem.clone(),
                last_msg_recvd_offset,
            )?,
            sender: LlmpSender::on_existing_shmem(
                shmem_provider,
                current_broker_shmem,
                last_msg_recvd_offset,
            )?,
        })
    }

    /// Recreate this client from a previous [`client.to_env()`]
    #[cfg(feature = "std")]
    pub fn on_existing_from_env(shmem_provider: SP, env_name: &str) -> Result<Self, Error> {
        Ok(Self {
            sender: LlmpSender::on_existing_from_env(
                shmem_provider.clone(),
                &format!("{env_name}_SENDER"),
            )?,
            receiver: LlmpReceiver::on_existing_from_env(
                shmem_provider,
                &format!("{env_name}_RECEIVER"),
            )?,
        })
    }

    /// Write the current state to env.
    /// A new client can attach to exactly the same state by calling [`LlmpClient::on_existing_shmem()`].
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) -> Result<(), Error> {
        self.sender.to_env(&format!("{env_name}_SENDER"))?;
        self.receiver.to_env(&format!("{env_name}_RECEIVER"))
    }

    /// Describe this client in a way that it can be recreated, for example after crash
    pub fn describe(&self) -> Result<LlmpClientDescription, Error> {
        Ok(LlmpClientDescription {
            sender: self.sender.describe()?,
            receiver: self.receiver.describe()?,
        })
    }

    /// Create an existing client from description
    pub fn existing_client_from_description(
        shmem_provider: SP,
        description: &LlmpClientDescription,
    ) -> Result<Self, Error> {
        Ok(Self {
            sender: LlmpSender::on_existing_from_description(
                shmem_provider.clone(),
                &description.sender,
            )?,
            receiver: LlmpReceiver::on_existing_from_description(
                shmem_provider,
                &description.receiver,
            )?,
        })
    }

    /// Outgoing channel to the broker
    #[must_use]
    pub fn sender(&self) -> &LlmpSender<SP> {
        &self.sender
    }

    /// Outgoing channel to the broker (mut)
    #[must_use]
    pub fn sender_mut(&mut self) -> &mut LlmpSender<SP> {
        &mut self.sender
    }

    /// Incoming (broker) broadcast map
    #[must_use]
    pub fn receiver(&self) -> &LlmpReceiver<SP> {
        &self.receiver
    }

    /// Incoming (broker) broadcast map (mut)
    #[must_use]
    pub fn receiver_mut(&mut self) -> &mut LlmpReceiver<SP> {
        &mut self.receiver
    }

    /// Waits for the sender to be save to unmap.
    /// If a receiver is involved on the other side, this function should always be called.
    pub fn await_safe_to_unmap_blocking(&self) {
        self.sender.await_safe_to_unmap_blocking();
    }

    /// If we are allowed to unmap this client
    pub fn safe_to_unmap(&self) -> bool {
        self.sender.safe_to_unmap()
    }

    /// For debug purposes: mark the client as save to unmap, even though it might not have been read.
    ///
    /// # Safety
    /// This should only be called in a debug scenario.
    /// Calling this in other contexts may lead to a premature page unmap and result in a crash in another process,
    /// or an unexpected read from an empty page in a receiving process.
    pub unsafe fn mark_safe_to_unmap(&mut self) {
        self.sender.mark_safe_to_unmap();
    }

    /// Creates a new [`LlmpClient`]
    pub fn new(
        mut shmem_provider: SP,
        initial_broker_shmem: LlmpSharedMap<SP::ShMem>,
        sender_id: ClientId,
    ) -> Result<Self, Error> {
        Ok(Self {
            sender: LlmpSender {
                id: sender_id,
                last_msg_sent: ptr::null_mut(),
                out_shmems: vec![LlmpSharedMap::new(sender_id, {
                    shmem_provider.new_shmem(LLMP_CFG_INITIAL_MAP_SIZE)?
                })],
                // drop pages to the broker if it already read them
                keep_pages_forever: false,
                has_unsent_message: false,
                shmem_provider: shmem_provider.clone(),
                unused_shmem_cache: vec![],
            },

            receiver: LlmpReceiver {
                id: ClientId(0),
                current_recv_shmem: initial_broker_shmem,
                last_msg_recvd: ptr::null_mut(),
                shmem_provider,
                highest_msg_id: MessageId(0),
                // We don't know the last received time, just assume the current time.
                #[cfg(feature = "std")]
                last_msg_time: current_time(),
            },
        })
    }

    /// Create a point-to-point channel instead of using a broker-client channel
    pub fn new_p2p(shmem_provider: SP, sender_id: ClientId) -> Result<Self, Error> {
        let sender = LlmpSender::new(shmem_provider.clone(), sender_id, false)?;
        let receiver = LlmpReceiver::on_existing_shmem(
            shmem_provider,
            sender.out_shmems[0].shmem.clone(),
            None,
        )?;
        Ok(Self { sender, receiver })
    }

    /// Commits a msg to the client's out map
    /// # Safety
    /// Needs to be called with a proper msg pointer
    pub unsafe fn send(&mut self, msg: *mut LlmpMsg) -> Result<(), Error> {
        self.sender.send(msg, true)
    }

    /// Allocates a message of the given size, tags it, and sends it off.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        self.sender.send_buf(tag, buf)
    }

    /// Send a `buf` with the given `flags`.
    pub fn send_buf_with_flags(&mut self, tag: Tag, flags: Flags, buf: &[u8]) -> Result<(), Error> {
        self.sender.send_buf_with_flags(tag, flags, buf)
    }

    /// Informs the broker about a new client in town, with the given map id
    pub fn send_client_added_msg(
        &mut self,
        shm_str: &[u8; 20],
        shm_id: usize,
    ) -> Result<(), Error> {
        // We write this by hand to get around checks in send_buf
        unsafe {
            let msg = self
                .alloc_next(size_of::<LlmpPayloadSharedMapInfo>())
                .expect("Could not allocate a new message in shared map.");
            (*msg).tag = LLMP_TAG_NEW_SHM_CLIENT;
            #[allow(clippy::cast_ptr_alignment)]
            let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;
            (*pageinfo).shm_str = *shm_str;
            (*pageinfo).map_size = shm_id;
            self.send(msg)
        }
    }

    /// A client receives a broadcast message.
    /// Returns null if no message is availiable
    /// # Safety
    /// Should be save, unless the internal state is corrupt. Returns raw ptr.
    #[inline]
    pub unsafe fn recv(&mut self) -> Result<Option<*mut LlmpMsg>, Error> {
        self.receiver.recv()
    }

    /// A client blocks/spins until the next message gets posted to the page,
    /// then returns that message.
    /// # Safety
    /// Should be save, unless the internal state is corrupt. Returns raw ptr.
    #[inline]
    pub unsafe fn recv_blocking(&mut self) -> Result<*mut LlmpMsg, Error> {
        self.receiver.recv_blocking()
    }

    /// The current page could have changed in recv (EOP).
    /// Alloc the next message, internally handling end of page by allocating a new one.
    /// # Safety
    /// Should be safe, but returns an unsafe ptr
    #[inline]
    pub unsafe fn alloc_next(&mut self, buf_len: usize) -> Result<*mut LlmpMsg, Error> {
        self.sender.alloc_next(buf_len)
    }

    /// Returns the next message, tag, buf, if available, else None
    #[allow(clippy::type_complexity)]
    #[inline]
    pub fn recv_buf(&mut self) -> Result<Option<(ClientId, Tag, &[u8])>, Error> {
        self.receiver.recv_buf()
    }

    /// Receives a buf from the broker, looping until a message becomes available
    #[inline]
    pub fn recv_buf_blocking(&mut self) -> Result<(ClientId, Tag, &[u8]), Error> {
        self.receiver.recv_buf_blocking()
    }

    /// Receive a `buf` from the broker, including the `flags` used during transmission.
    #[allow(clippy::type_complexity)]
    pub fn recv_buf_with_flags(&mut self) -> Result<Option<(ClientId, Tag, Flags, &[u8])>, Error> {
        self.receiver.recv_buf_with_flags()
    }

    #[cfg(feature = "std")]
    /// Creates a new [`LlmpClient`], reading the map id and len from env
    pub fn create_using_env(mut shmem_provider: SP, env_var: &str) -> Result<Self, Error> {
        let map = LlmpSharedMap::existing(shmem_provider.existing_from_env(env_var)?);
        let client_id = unsafe { (*map.page()).sender_id };
        Self::new(shmem_provider, map, client_id)
    }

    #[cfg(feature = "std")]
    /// Create a [`LlmpClient`], getting the ID from a given port
    pub fn create_attach_to_tcp(mut shmem_provider: SP, port: u16) -> Result<Self, Error> {
        let mut stream = match TcpStream::connect((_LLMP_CONNECT_ADDR, port)) {
            Ok(stream) => stream,
            Err(e) => {
                match e.kind() {
                    ErrorKind::ConnectionRefused => {
                        //connection refused. loop till the broker is up
                        loop {
                            match TcpStream::connect((_LLMP_CONNECT_ADDR, port)) {
                                Ok(stream) => break stream,
                                Err(_) => {
                                    log::info!("Connection Refused.. Retrying");
                                }
                            }
                        }
                    }
                    _ => return Err(Error::illegal_state(e.to_string())),
                }
            }
        };
        log::info!("Connected to port {port}");

        let TcpResponse::BrokerConnectHello {
            broker_shmem_description,
            hostname: _,
        } = recv_tcp_msg(&mut stream)?.try_into()?
        else {
            return Err(Error::illegal_state(
                "Received unexpected Broker Hello".to_string(),
            ));
        };

        let map = LlmpSharedMap::existing(
            shmem_provider.shmem_from_description(broker_shmem_description)?,
        );

        // We'll set `sender_id` later
        let mut ret = Self::new(shmem_provider, map, ClientId(0))?;

        let client_hello_req = TcpRequest::LocalClientHello {
            shmem_description: ret.sender.out_shmems.first().unwrap().shmem.description(),
        };

        send_tcp_msg(&mut stream, &client_hello_req)?;

        let TcpResponse::LocalClientAccepted { client_id } =
            recv_tcp_msg(&mut stream)?.try_into()?
        else {
            return Err(Error::illegal_state(
                "Unexpected Response from Broker".to_string(),
            ));
        };

        // Set our ID to the one the broker sent us..
        // This is mainly so we can filter out our own msgs later.
        ret.sender.id = client_id;
        // Also set the sender on our initial llmp map correctly.
        unsafe {
            (*ret.sender.out_shmems.first_mut().unwrap().page_mut()).sender_id = client_id;
        }

        Ok(ret)
    }
}

#[cfg(test)]
#[cfg(all(unix, feature = "std", not(target_os = "haiku")))]
mod tests {

    use std::{thread::sleep, time::Duration};

    use serial_test::serial;

    use super::{
        LlmpClient,
        LlmpConnection::{self, IsBroker, IsClient},
        LlmpMsgHookResult::ForwardToClients,
        Tag, DEFAULT_CLIENT_TIMEOUT_SECS,
    };
    use crate::shmem::{ShMemProvider, StdShMemProvider};

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    pub fn test_llmp_connection() {
        #[allow(unused_variables)]
        let shmem_provider = StdShMemProvider::new().unwrap();
        let mut broker = match LlmpConnection::on_port(
            shmem_provider.clone(),
            1337,
            DEFAULT_CLIENT_TIMEOUT_SECS,
        )
        .unwrap()
        {
            IsClient { client: _ } => panic!("Could not bind to port as broker"),
            IsBroker { broker } => broker,
        };

        // Add the first client (2nd, actually, because of the tcp listener client)
        let mut client = match LlmpConnection::on_port(
            shmem_provider.clone(),
            1337,
            DEFAULT_CLIENT_TIMEOUT_SECS,
        )
        .unwrap()
        {
            IsBroker { broker: _ } => panic!("Second connect should be a client!"),
            IsClient { client } => client,
        };

        // Give the (background) tcp thread a few millis to post the message
        sleep(Duration::from_millis(100));
        broker
            .once(&mut |_sender_id, _tag, _flags, _msg| Ok(ForwardToClients))
            .unwrap();

        let tag: Tag = Tag(0x1337);
        let arr: [u8; 1] = [1_u8];
        // Send stuff
        client.send_buf(tag, &arr).unwrap();

        client.to_env("_ENV_TEST").unwrap();
        #[cfg(all(feature = "llmp_debug", feature = "std"))]
        log::info!("{:?}", std::env::vars());

        for (key, value) in std::env::vars_os() {
            log::info!("{key:?}: {value:?}");
        }

        /* recreate the client from env, check if it still works */
        client = LlmpClient::on_existing_from_env(shmem_provider, "_ENV_TEST").unwrap();

        client.send_buf(tag, &arr).unwrap();

        // Forward stuff to clients
        broker
            .once(&mut |_sender_id, _tag, _flags, _msg| Ok(ForwardToClients))
            .unwrap();
        let (_sender_id, tag2, arr2) = client.recv_buf_blocking().unwrap();
        assert_eq!(tag, tag2);
        assert_eq!(arr[0], arr2[0]);

        // We want at least the tcp and sender clients.
        assert_eq!(broker.llmp_clients.len(), 2);
    }
}
