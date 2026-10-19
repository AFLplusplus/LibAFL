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
with the main thread using [`LlmpBrokerInner::register_client`].
Finally, call [`LlmpBroker::loop_forever()`].

For broker2broker communication, all messages are forwarded via network sockets.

Check out the `llmp_test` example in ./examples, or build it with `cargo run --example llmp_test`.

*/
#![doc = include_str!("../README.md")]
/*! */
#![cfg_attr(feature = "document-features", doc = document_features::document_features!())]
#![no_std]
#![cfg_attr(not(test), warn(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    //unused_results
))]
#![cfg_attr(test, deny(
    missing_debug_implementations,
    missing_docs,
    //trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_must_use,
    //unused_results
))]
#![cfg_attr(
    test,
    deny(
        bad_style,
        dead_code,
        improper_ctypes,
        non_shorthand_field_patterns,
        overflowing_literals,
        path_statements,
        patterns_in_fns_without_body,
        unconditional_recursion,
        unused,
        unused_allocation,
        unused_comparisons,
        unused_parens,
        while_true
    )
)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use alloc::boxed::Box;
#[cfg(feature = "std")]
use alloc::string::ToString;
#[cfg(feature = "std")]
use alloc::sync::Arc;
use alloc::{string::String, vec, vec::Vec};
#[cfg(any(unix, all(windows, feature = "std")))]
use core::sync::atomic::AtomicBool;
#[cfg(not(target_pointer_width = "64"))]
use core::sync::atomic::AtomicU32;
#[cfg(target_pointer_width = "64")]
use core::sync::atomic::AtomicU64;
#[cfg(feature = "std")]
use core::sync::atomic::AtomicUsize;
use core::{
    cmp::max,
    fmt::Debug,
    hint,
    mem::size_of,
    num::NonZeroUsize,
    ops::{BitAnd, BitOr, Not},
    ptr, slice,
    sync::atomic::{AtomicU16, Ordering, fence},
    time::Duration,
};
#[cfg(feature = "std")]
use core::{mem::offset_of, net::SocketAddr, ptr::write_unaligned};
#[cfg(all(debug_assertions, feature = "llmp_debug", feature = "std"))]
use std::backtrace::Backtrace;
#[cfg(feature = "std")]
use std::{
    env,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream, ToSocketAddrs},
    sync::mpsc::channel,
    thread,
};

#[cfg(all(unix, feature = "alloc"))]
use exceptional::unix_signals::SignalHandler;
#[cfg(all(unix, feature = "alloc", not(miri)))]
use exceptional::unix_signals::setup_signal_handler;
#[cfg(all(unix, feature = "alloc"))]
use exceptional::unix_signals::{Signal, siginfo_t, ucontext_t};
#[cfg(all(windows, feature = "std"))]
use exceptional::windows_exceptions::{CtrlHandler, setup_ctrl_handler};
#[cfg(feature = "std")]
use libafl_core::IP_LOCALHOST;
use libafl_core::{ClientId, Error, format};
#[cfg(all(unix, feature = "std"))]
#[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
use nix::sys::socket;
#[cfg(feature = "std")]
use no_std_time::current_time;
use serde::{Deserialize, Serialize};
use shmem_providers::{ShMem, ShMemDescription, ShMemId, ShMemProvider};
#[cfg(feature = "std")]
use tuple_list::tuple_list;

/// The max number of pages a client may have mapped that were not yet read by the broker
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
/// A client wants to disconnect from this broker
const LLMP_TAG_CLIENT_EXIT: Tag = Tag(0xC11E472);
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
/// From another machine (with the `multi_machine` mode)
pub const LLMP_FLAG_FROM_MM: Flags = Flags(0x4);

/// Timt the broker 2 broker connection waits for incoming data,
/// before checking for own data to forward again.
const _LLMP_B2B_BLOCK_TIME: Duration = Duration::from_secs(3);

/// If broker2broker is enabled, bind to public IP
#[cfg(feature = "llmp_bind_public")]
const _LLMP_BIND_ADDR: &str = "0.0.0.0";

/// If broker2broker is disabled, bind to localhost
#[cfg(not(feature = "llmp_bind_public"))]
const _LLMP_BIND_ADDR: &str = "127.0.0.1";

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
    shutting_down: AtomicBool::new(false),
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
/// If an `llmp` connection is local - use sharedmaps
/// or remote (`broker2broker`) - forwarded via tcp
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
    /// Notify the broker the the othe side is dying so remove this client
    /// `client_id` is the pid of the very initial client
    ClientQuit {
        /// Tell the broker that remove the client with this `client_id`. `client_id` is equal to the one of event restarter
        client_id: ClientId,
    },
}

#[cfg(feature = "std")]
impl TryFrom<&Vec<u8>> for TcpRequest {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Error> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
impl TryFrom<&Vec<u8>> for TcpRemoteNewMessage {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Error> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
impl TryFrom<&Vec<u8>> for TcpResponse {
    type Error = Error;

    fn try_from(bytes: &Vec<u8>) -> Result<Self, Error> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

#[cfg(feature = "std")]
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
    fn accept(&self) -> Result<ListenerStream, io::Error> {
        match self {
            Listener::Tcp(inner) => match inner.accept() {
                Ok(res) => Ok(ListenerStream::Tcp(res.0, res.1)),
                Err(err) => Err(err),
            },
        }
    }
}

/// Get sharedmem from a page
#[inline]
#[expect(clippy::cast_ptr_alignment)]
unsafe fn shmem2page_mut<SHM: ShMem>(afl_shmem: &mut SHM) -> *mut LlmpPage {
    afl_shmem.as_mut_ptr() as *mut LlmpPage
}

/// Pointer to the first message slot on `page`, avoiding 0-size sub-object provenance on `(*page).messages`.
#[inline]
#[expect(clippy::cast_ptr_alignment)]
const unsafe fn llmp_page_messages_ptr(page: *const LlmpPage) -> *const LlmpMsg {
    unsafe {
        (page as *const u8)
            .add(LLMP_PAGE_HEADER_LEN)
            .cast::<LlmpMsg>()
    }
}

/// Mutable pointer to the first message slot on `page`, avoiding 0-size sub-object provenance on `(*page).messages`.
#[inline]
#[expect(clippy::cast_ptr_alignment)]
const unsafe fn llmp_page_messages_mut_ptr(page: *mut LlmpPage) -> *mut LlmpMsg {
    unsafe {
        (page as *mut u8)
            .add(LLMP_PAGE_HEADER_LEN)
            .cast::<LlmpMsg>()
    }
}

/// Mutable pointer to the payload buffer following `msg`, avoiding 0-size sub-object provenance on `(*msg).buf`.
#[inline]
const unsafe fn llmp_msg_buf_mut_ptr(msg: *mut LlmpMsg) -> *mut u8 {
    unsafe { (msg as *mut u8).add(size_of::<LlmpMsg>()) }
}

/// Return, if a msg is contained in the current page
#[inline]
unsafe fn llmp_msg_in_page(page: *const LlmpPage, msg: *const LlmpMsg) -> bool {
    unsafe {
        /* DBG("llmp_msg_in_page %p within %p-%p\n", msg, page, page + page->size_total); */
        let page_addr = page as usize;
        let msg_addr = msg as usize;
        let Some(messages_start) = page_addr.checked_add(LLMP_PAGE_HEADER_LEN) else {
            return false;
        };
        let Some(page_end) = messages_start.checked_add((*page).size_total) else {
            return false;
        };
        let Some(msg_header_end) = msg_addr.checked_add(size_of::<LlmpMsg>()) else {
            return false;
        };
        msg_addr >= messages_start && msg_header_end <= page_end
    }
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
/// Will set `SO_REUSEADDR` on unix.
#[cfg(feature = "std")]
fn tcp_bind(port: u16) -> Result<TcpListener, Error> {
    let listener = TcpListener::bind((_LLMP_BIND_ADDR, port)).map_err(|err| {
        let err_msg = format!("Failed to bind to port {port}: {err}");
        Error::os_error(err, err_msg)
    })?;

    #[cfg(unix)]
    #[cfg(not(any(target_os = "solaris", target_os = "illumos")))]
    socket::setsockopt(&listener, socket::sockopt::ReuseAddr, &true)?;

    Ok(listener)
}

/// Send one message as `u32` len and `[u8;len]` bytes
#[cfg(feature = "std")]
pub fn send_tcp_msg<T>(stream: &mut TcpStream, msg: &T) -> Result<(), Error>
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
pub fn recv_tcp_msg(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
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

    stream.read_exact(&mut bytes)?;
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
    unsafe {
        #[cfg(feature = "llmp_debug")]
        log::trace!("llmp_page_init: shmem {shmem:?}");
        let map_size = shmem.len();
        let page = shmem2page_mut(shmem);
        #[cfg(feature = "llmp_debug")]
        log::trace!("llmp_page_init: page {:?}", *page);

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
        #[expect(clippy::cast_ptr_alignment)]
        let first_msg = (page as *mut u8)
            .add(LLMP_PAGE_HEADER_LEN)
            .cast::<LlmpMsg>();
        (*first_msg).message_id = MessageId(0);
        (*first_msg).tag = LLMP_TAG_UNSET;
        (*page).receivers_joined_count.store(0, Ordering::Release);
        (*page).receivers_left_count.store(0, Ordering::Relaxed);
        assert!((*page).size_total != 0);
    }
}

/// Get the next pointer and make sure it's in the current page, and has enough space.
///
/// # Safety
/// Will dereference `last_msg`
#[inline]
#[expect(clippy::cast_ptr_alignment)]
unsafe fn llmp_next_msg_ptr_checked<SHM: ShMem>(
    map: &mut LlmpSharedMap<SHM>,
    last_msg: *const LlmpMsg,
    alloc_size: usize,
) -> Result<*mut LlmpMsg, Error> {
    unsafe {
        let page = map.page_mut();
        let page_addr = page as usize;
        let map_size = map.map_size;
        let msg_begin_min = page_addr + size_of::<LlmpPage>();

        let Some(max_offset) = map_size.checked_sub(alloc_size) else {
            return Err(Error::illegal_state(format!(
                "Inconsistent data on sharedmap, or Bug (alloc_size {alloc_size} > map_size {map_size})"
            )));
        };
        let msg_begin_max = page_addr + max_offset;

        let last_msg_addr = last_msg as usize;
        let next_addr = usize::try_from((*last_msg).buf_len_padded)
            .ok()
            .and_then(|padded| size_of::<LlmpMsg>().checked_add(padded))
            .and_then(|step| last_msg_addr.checked_add(step));

        if let Some(next_addr) = next_addr
            && next_addr >= msg_begin_min
            && next_addr <= msg_begin_max
        {
            let offset = next_addr - page_addr;
            Ok((page as *mut u8).add(offset) as *mut LlmpMsg)
        } else {
            Err(Error::illegal_state(format!(
                "Inconsistent data on sharedmap, or Bug (next_ptr was {next_addr:?}, sharedmap page was {page_addr:x})"
            )))
        }
    }
}

/// Pointer to the message behind the last message
/// The messages are padded, so accesses will be aligned properly.
///
/// # Safety
/// Will dereference the `last_msg` ptr
#[inline]
#[expect(clippy::cast_ptr_alignment)]
unsafe fn llmp_next_msg_ptr(last_msg: *const LlmpMsg) -> *mut LlmpMsg {
    unsafe {
        /* DBG("llmp_next_msg_ptr %p %lu + %lu\n", last_msg, last_msg->buf_len_padded, sizeof(llmp_message)); */
        (last_msg as *mut u8)
            .add(size_of::<LlmpMsg>())
            .add((*last_msg).buf_len_padded as usize) as *mut LlmpMsg
    }
}

/// Description of a shared map.
/// May be used to restore the map by id.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct LlmpDescription {
    /// Info about the [`ShMem`] in use
    shmem: ShMemDescription,
    /// The last message sent or received, depnding on page type
    last_message_offset: Option<u64>,
}

#[derive(Debug, Copy, Clone)]
/// Result of an LLMP Message hook
pub enum LlmpMsgHookResult {
    /// This has been handled in the broker. No need to forward.
    Handled,
    /// Forward this to the clients. We are not done here.
    ForwardToClients,
}

/// Message sent over the "wire"
#[derive(Debug, Copy, Clone)]
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
    /// Gets the buffer from a raw pointer to a message as a slice, with the correct length.
    ///
    /// # Safety
    /// `this` must be a valid pointer to a message followed by `buf_len` bytes.
    #[must_use]
    pub unsafe fn as_slice_raw<'a>(this: *const Self) -> &'a [u8] {
        unsafe {
            let ptr = (this as *const u8).add(size_of::<Self>());
            let len = (*this).buf_len as usize;
            slice::from_raw_parts(ptr, len)
        }
    }

    /// Gets the buffer from a raw pointer to a message as a mutable slice, with the correct length.
    ///
    /// # Safety
    /// `this` must be a valid pointer to a message followed by `buf_len` bytes.
    #[must_use]
    pub unsafe fn as_slice_mut_raw<'a>(this: *mut Self) -> &'a mut [u8] {
        unsafe {
            let ptr = (this as *mut u8).add(size_of::<Self>());
            let len = (*this).buf_len as usize;
            slice::from_raw_parts_mut(ptr, len)
        }
    }

    /// Gets the buffer from this message as slice, with the correct length.
    ///
    /// # Safety
    /// This is unsafe if somebody has access to shared mem pages on the system.
    #[must_use]
    pub unsafe fn as_slice_unsafe(&self) -> &[u8] {
        unsafe { Self::as_slice_raw(ptr::from_ref(self)) }
    }

    /// Gets the buffer from this message as a mutable slice, with the correct length.
    ///
    /// # Safety
    /// This is unsafe if somebody has access to shared mem pages on the system.
    #[must_use]
    pub unsafe fn as_slice_mut_unsafe(&mut self) -> &mut [u8] {
        unsafe { Self::as_slice_mut_raw(ptr::from_mut(self)) }
    }

    /// Gets the buffer from this message as slice, with the correct length.
    #[inline]
    pub fn try_as_slice<'a, SHM: ShMem>(
        &self,
        map: &'a LlmpSharedMap<SHM>,
    ) -> Result<&'a [u8], Error> {
        if self.in_shmem(map) {
            let page_ptr = unsafe { map.page().cast::<u8>() };
            let offset = (ptr::from_ref(self) as usize) - (page_ptr as usize) + size_of::<Self>();
            let len = self.buf_len as usize;
            let slice = unsafe { slice::from_raw_parts(page_ptr.add(offset), len) };
            Ok(slice)
        } else {
            Err(Error::illegal_state(
                "Current message not in page. The sharedmap get tampered with or we have a BUG.",
            ))
        }
    }

    /// Gets the buffer from this message as mutable slice, with the correct length.
    #[inline]
    pub fn try_as_slice_mut<'a, SHM: ShMem>(
        &mut self,
        map: &'a mut LlmpSharedMap<SHM>,
    ) -> Result<&'a mut [u8], Error> {
        if self.in_shmem(map) {
            let page_ptr = unsafe { map.page_mut().cast::<u8>() };
            let offset = (ptr::from_ref(self) as usize) - (page_ptr as usize) + size_of::<Self>();
            let len = self.buf_len as usize;
            let slice = unsafe { slice::from_raw_parts_mut(page_ptr.add(offset), len) };
            Ok(slice)
        } else {
            Err(Error::illegal_state(
                "Current message not in page. The sharedmap get tampered with or we have a BUG.",
            ))
        }
    }

    /// Returns `true`, if the pointer is, indeed, in the page of this shared map.
    #[inline]
    pub fn in_shmem<SHM: ShMem>(&self, map: &LlmpSharedMap<SHM>) -> bool {
        let msg_addr = ptr::from_ref(self) as usize;
        let page_addr = unsafe { map.page() } as usize;
        let map_size = map.map_size;

        if msg_addr < page_addr {
            return false;
        }
        let offset = msg_addr - page_addr;

        if offset < size_of::<LlmpPage>() {
            return false;
        }

        let Some(header_end) = offset.checked_add(size_of::<LlmpMsg>()) else {
            return false;
        };

        if header_end > map_size {
            return false;
        }

        let max_buf_len = (map_size - header_end) as u64;

        self.buf_len <= self.buf_len_padded && self.buf_len_padded <= max_buf_len
    }
}

/// An Llmp instance
#[derive(Debug)]
pub enum LlmpConnection<HT, SHM, SP> {
    /// A broker and a thread using this tcp background thread
    IsBroker {
        /// The [`LlmpBroker`] of this [`LlmpConnection`].
        broker: LlmpBroker<HT, SHM, SP>,
    },
    /// A client, connected to the port
    IsClient {
        /// The [`LlmpClient`] of this [`LlmpConnection`].
        client: LlmpClient<SHM, SP>,
    },
}

impl<SHM, SP> LlmpConnection<(), SHM, SP>
where
    SHM: ShMem,
    SP: ShMemProvider<ShMem = SHM>,
{
    #[cfg(feature = "std")]
    /// Creates either a broker, if the tcp port is not bound, or a client, connected to this port.
    /// This will make a new connection to the broker if it ends up a client
    /// In that case this function will return its new [`ClientId`], too.
    pub fn on_port(shmem_provider: SP, port: u16) -> Result<Self, Error> {
        match tcp_bind(port) {
            Ok(listener) => {
                // We got the port. We are the broker! :)
                log::info!("We're the broker");

                let mut broker = LlmpBroker::new(shmem_provider, tuple_list!())?;
                let _listener_thread = broker
                    .inner_mut()
                    .launch_listener(Listener::Tcp(listener))?;
                Ok(LlmpConnection::IsBroker { broker })
            }
            Err(Error::OsError(e, ..)) if e.kind() == io::ErrorKind::AddrInUse => {
                // We are the client :)
                log::info!("We're the client (internal port already bound by broker, {e:#?})");
                let client = LlmpClient::create_attach_to_tcp(shmem_provider, port)?;
                let conn = LlmpConnection::IsClient { client };
                Ok(conn)
            }
            Err(e) => {
                log::error!("{e:?}");
                Err(e)
            }
        }
    }

    /// Creates a new broker on the given port
    #[cfg(feature = "std")]
    pub fn broker_on_port(shmem_provider: SP, port: u16) -> Result<Self, Error> {
        Ok(LlmpConnection::IsBroker {
            broker: LlmpBroker::create_attach_to_tcp(shmem_provider, tuple_list!(), port)?,
        })
    }

    /// Creates a new client on the given port
    /// This will make a new connection to the broker if it ends up a client
    /// In that case this function will return its new [`ClientId`], too.
    #[cfg(feature = "std")]
    pub fn client_on_port(shmem_provider: SP, port: u16) -> Result<Self, Error> {
        let client = LlmpClient::create_attach_to_tcp(shmem_provider, port)?;
        let conn = LlmpConnection::IsClient { client };
        Ok(conn)
    }
}

impl<MT, SHM, SP> LlmpConnection<MT, SHM, SP>
where
    MT: LlmpHookTuple<SHM, SP>,
    SHM: ShMem,
    SP: ShMemProvider<ShMem = SHM>,
{
    /// Describe this in a reproducible fashion, if it's a client
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
    ) -> Result<LlmpConnection<MT, SHM, SP>, Error> {
        Ok(LlmpConnection::IsClient {
            client: LlmpClient::existing_client_from_description(shmem_provider, description)?,
        })
    }

    /// Sends the given buffer over this connection, no matter if client or broker.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        match self {
            LlmpConnection::IsBroker { broker } => broker.inner.send_buf(tag, buf),
            LlmpConnection::IsClient { client } => client.send_buf(tag, buf),
        }
    }

    /// Send the `buf` with given `flags`.
    pub fn send_buf_with_flags(&mut self, tag: Tag, buf: &[u8], flags: Flags) -> Result<(), Error> {
        match self {
            LlmpConnection::IsBroker { broker } => {
                broker.inner.send_buf_with_flags(tag, flags, buf)
            }
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
    /// It also servers to know whether the next message can be read or not.
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
    unsafe fn receiver_joined(this: *const Self) {
        let count = unsafe { &(*this).receivers_joined_count };
        #[cfg(target_has_atomic = "16")]
        count.fetch_add(1, Ordering::Release);
        #[cfg(not(target_has_atomic = "16"))]
        count.store(
            count.load(Ordering::Acquire).wrapping_add(1),
            Ordering::Release,
        );
    }

    #[inline]
    unsafe fn receiver_left(this: *const Self) {
        let count = unsafe { &(*this).receivers_left_count };
        #[cfg(target_has_atomic = "16")]
        count.fetch_add(1, Ordering::Release);
        #[cfg(not(target_has_atomic = "16"))]
        count.store(
            count.load(Ordering::Acquire).wrapping_add(1),
            Ordering::Release,
        );
    }
}

/// Message payload when a client got added */
/// This is an internal message!
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct LlmpPayloadSharedMapInfo {
    /// The map size
    pub map_size: usize,
    /// The id of this map, as 0-terminated c string of at most 19 chars
    pub shm_str: [u8; 20],
}

/// Message payload when a client got removed
/// This is an internal message!
#[derive(Debug, Copy, Clone)]
#[repr(C, align(8))]
struct LlmpClientExitInfo {
    /// The restarter process id of the client
    pub client_id: u32,
}

/// Sending end on a (unidirectional) sharedmap channel
#[derive(Debug)]
pub struct LlmpSender<SHM, SP> {
    /// ID of this sender.
    id: ClientId,
    /// Ref to the last message this sender sent on the last page.
    /// If null, a new page (just) started.
    last_msg_sent: *const LlmpMsg,
    /// A vec of page wrappers, each containing an initialized [`ShMem`]
    out_shmems: Vec<LlmpSharedMap<SHM>>,
    /// A vec of pages that we previously used, but that have served its purpose
    /// (no potential receivers are left).
    /// Instead of freeing them, we keep them around to potentially reuse them later,
    /// if they are still large enough.
    /// This way, the OS doesn't have to spend time zeroing pages, and getting rid of our old pages
    unused_shmem_cache: Vec<LlmpSharedMap<SHM>>,
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
impl<SHM, SP> LlmpSender<SHM, SP>
where
    SHM: ShMem,
    SP: ShMemProvider<ShMem = SHM>,
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
            ret.id
        );
        Ok(ret)
    }

    /// Reattach to a vacant `out_shmem`.
    /// It is essential, that the receiver (or someone else) keeps a pointer to this map
    /// else reattach will get a new, empty page, from the OS, or fail.
    pub fn on_existing_shmem(
        shmem_provider: SP,
        current_out_shmem: SHM,
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
            client_id
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
    /// eventually. This function sees if we can deallocate older pages.
    /// The broker would have informed us by setting the safe_to_unmap-flag.
    unsafe fn prune_old_pages(&mut self) {
        unsafe {
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
                // We send one last information to the broker before quitting, if space remains on the current page.
                if !self.has_unsent_message
                    && let Some(msg) = self.alloc_next_if_space(0)
                {
                    (*msg).tag = LLMP_SLOW_RECEIVER_PANIC;
                    (*msg).flags = LLMP_FLAG_INITIALIZED;
                    self.send(msg, true).unwrap();
                }
                panic!(
                    "The receiver/broker could not process our sent llmp messages in time. Either we're sending too many messages too fast, the broker got stuck, or it crashed. Giving up."
                );
            }

            // Remove all maps that the broker already mapped, move them to our unused pages cache
            self.out_shmems.reserve(unmap_until_excl);
            for _ in 0..unmap_until_excl {
                let mut map = self.out_shmems.remove(0);

                let page = map.page_mut();
                assert!(
                    (*page).magic == PAGE_INITIALIZED_MAGIC,
                    "LLMP: Tried to free uninitialized shared map at addr {:#}!",
                    page as usize
                );

                #[cfg(feature = "llmp_debug")]
                log::debug!("Moving unused map to cache: {map:?} {:x?}", map.page());
                self.unused_shmem_cache
                    .insert(self.unused_shmem_cache.len(), map);
            }
        }
    }

    /// Grab an unused `LlmpSharedMap` from `unused_shmem_cache` or allocate a new map,
    /// if no suitable maps could be found.
    unsafe fn new_or_unused_shmem(
        &mut self,
        sender_id: ClientId,
        next_min_shmem_size: usize,
    ) -> Result<LlmpSharedMap<SHM>, Error> {
        unsafe {
            // Find a shared map that has been released to reuse, from which all receivers left / finished reading.
            let cached_shmem = self
                .unused_shmem_cache
                .iter()
                .position(|cached_shmem| {
                    let page = cached_shmem.page();
                    let receivers_joined_count =
                        (*page).receivers_joined_count.load(Ordering::Acquire);
                    debug_assert_ne!(receivers_joined_count, 0);
                    let receivers_left_count = (*page).receivers_left_count.load(Ordering::Acquire);
                    debug_assert!(receivers_joined_count >= receivers_left_count);

                    let ret = receivers_joined_count == receivers_left_count;

                    // For proper refcounts, double check that nobody joined in the meantime.
                    debug_assert_eq!(
                        receivers_joined_count,
                        (*page).receivers_joined_count.load(Ordering::Acquire),
                        "Oops, some receiver joined while re-using the page!"
                    );

                    ret
                })
                .map(|e| self.unused_shmem_cache.remove(e));

            match cached_shmem {
                Some(mut cached_shmem) => {
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
                        let page = cached_shmem.page_mut();
                        (*page).magic = PAGE_DEINITIALIZED_MAGIC;
                        llmp_page_init(&mut cached_shmem.shmem, sender_id, false);
                        cached_shmem.page = shmem2page_mut(&mut cached_shmem.shmem);
                        Ok(cached_shmem)
                    }
                }
                _ => {
                    // No cached maps that fit our need, let's allocate a new one.
                    Ok(LlmpSharedMap::new(
                        sender_id,
                        self.shmem_provider.new_shmem(next_min_shmem_size)?,
                    ))
                }
            }
        }
    }

    /// listener about it using a EOP message.
    unsafe fn handle_out_eop(&mut self) -> Result<(), Error> {
        unsafe {
            #[cfg(all(feature = "llmp_debug", feature = "std"))]
            {
                #[cfg(debug_assertions)]
                let bt = Backtrace::capture();
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
            log::info!("Next min ShMem Size {next_min_shmem_size}");

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

            #[expect(clippy::cast_ptr_alignment)]
            let end_of_page_msg = llmp_msg_buf_mut_ptr(out).cast::<LlmpPayloadSharedMapInfo>();
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
    }

    /// Allocates the next space on this sender page
    pub fn alloc_next(&mut self, buf_len: usize) -> Result<*mut LlmpMsg, Error> {
        if let Some(msg) = unsafe { self.alloc_next_if_space(buf_len) } {
            return Ok(msg);
        }

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
        unsafe {
            /* DBG("Client %d cancels send of msg at %p with tag 0x%X and size %ld", client->id, msg, msg->tag,
             * msg->buf_len_padded); */
            let page = self.out_shmems.last_mut().unwrap().page_mut();
            (*msg).tag = LLMP_TAG_UNSET;
            (*page).size_used -= (*msg).buf_len_padded as usize + size_of::<LlmpMsg>();
            self.has_unsent_message = false;
        }
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
        unsafe {
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
                return Err(Error::illegal_argument(format!(
                    "Cannot shrink msg of size {} (paded: {old_len_padded}) to requested larger size of {shrinked_len} (padded: {buf_len_padded})!",
                    (*msg).buf_len
                )));
            }

            (*msg).buf_len = shrinked_len as u64;
            (*msg).buf_len_padded = buf_len_padded as u64;

            let page = self.out_shmems.last_mut().unwrap().page_mut();

            // Doing this step by step will catch underflows in debug builds :)
            (*page).size_used -= old_len_padded as usize;
            (*page).size_used += buf_len_padded;

            (*llmp_next_msg_ptr(msg)).tag = LLMP_TAG_UNSET;

            Ok(())
        }
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
                .copy_to_nonoverlapping(llmp_msg_buf_mut_ptr(msg), buf.len());
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
                .copy_to_nonoverlapping(llmp_msg_buf_mut_ptr(msg), buf.len());
            self.send(msg, true)
        }
    }

    /// Create this client on an existing map from the given description.
    /// Acquired with [`LlmpSender::describe`].
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

impl<SHM, SP> LlmpSender<SHM, SP>
where
    SHM: ShMem,
{
    /// ID of this sender.
    #[must_use]
    pub fn id(&self) -> ClientId {
        self.id
    }

    /// Set the ID of this sender.
    pub fn set_id(&mut self, id: ClientId) {
        self.id = id;
    }

    /// Completely reset the current sender map.
    /// Afterwards, no receiver should read from it at a different location.
    /// This is only useful if all connected llmp parties start over, for example after a crash.
    ///
    /// # Safety
    /// Only safe if you really really restart the page on everything connected
    /// No receiver should read from this page at a different location.
    pub unsafe fn reset(&mut self) {
        unsafe {
            let current_out_shmem = self.out_shmems.last_mut().unwrap();
            llmp_page_init(&mut current_out_shmem.shmem, self.id, true);
            current_out_shmem.page = shmem2page_mut(&mut current_out_shmem.shmem);
            self.last_msg_sent = ptr::null_mut();
            self.has_unsent_message = false;
        }
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
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { env::set_var(format!("{env_name}_CLIENT_ID"), format!("{}", id.0)) };
    }

    /// Store the info to this sender to env.
    /// A new client can reattach to it using [`LlmpSender::on_existing_from_env()`].
    ///
    /// # Safety
    /// Writes to env variables and may only be done single-threaded.
    #[cfg(feature = "std")]
    pub unsafe fn to_env(&self, env_name: &str) -> Result<(), Error> {
        unsafe {
            let current_out_shmem = self.out_shmems.last().unwrap();
            current_out_shmem.shmem.write_to_env(env_name)?;
            Self::client_id_to_env(env_name, self.id);
            current_out_shmem.msg_to_env(self.last_msg_sent, env_name)
        }
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
                .load(Ordering::Acquire)
                >= 1
        }
    }

    /// For debug purposes: Mark save to unmap, even though it might not have been read by a receiver yet.
    /// # Safety
    /// If this method is called, the page may be unmapped before it is read by any receiver.
    pub unsafe fn mark_safe_to_unmap(&mut self) {
        unsafe {
            LlmpPage::receiver_joined(self.out_shmems.last_mut().unwrap().page_mut());
        }
    }

    /// Intern: Special allocation function for `EOP` messages (and nothing else!)
    /// The normal alloc will fail if there is not enough space for `buf_len_padded + EOP`
    /// So if [`Self::alloc_next`] fails, create new page if necessary, use this function,
    /// place `EOP`, commit `EOP`, reset, alloc again on the new space.
    unsafe fn alloc_eop(&mut self) -> Result<*mut LlmpMsg, Error> {
        unsafe {
            let map = self.out_shmems.last_mut().unwrap();
            let page = map.page_mut();
            let last_msg = self.last_msg_sent;
            assert!(
                (*page).size_used + EOP_MSG_SIZE <= (*page).size_total,
                "PROGRAM ABORT : BUG: EOP does not fit in page! page {page:?}, size_current {:?}, size_total {:?}",
                &raw const (*page).size_used,
                &raw const (*page).size_total
            );

            let ret: *mut LlmpMsg = if last_msg.is_null() {
                #[expect(clippy::cast_ptr_alignment)]
                page.cast::<u8>()
                    .add(LLMP_PAGE_HEADER_LEN + (*page).size_used)
                    .cast::<LlmpMsg>()
            } else {
                llmp_next_msg_ptr_checked(map, last_msg, EOP_MSG_SIZE)?
            };
            assert!(
                !self.has_unsent_message && (*ret).tag != LLMP_TAG_UNINITIALIZED,
                "Did not call send() on last message!"
            );

            (*ret).buf_len = size_of::<LlmpPayloadSharedMapInfo>() as u64;

            // We don't need to pad the EOP message: it'll always be the last in this page.
            (*ret).buf_len_padded = (*ret).buf_len;
            (*ret).message_id = if last_msg.is_null() {
                MessageId((*page).current_msg_id.load(Ordering::Relaxed) + 1)
            } else {
                MessageId((*last_msg).message_id.0 + 1)
            };
            (*ret).tag = LLMP_TAG_END_OF_PAGE;
            (*page).size_used += EOP_MSG_SIZE;
            Ok(ret)
        }
    }

    /// Intern: Will return a ptr to the next msg buf, or None if map is full.
    /// Never call [`Self::alloc_next`] without either sending or cancelling the last allocated message for this page!
    /// There can only ever be up to one message allocated per page at each given time.
    unsafe fn alloc_next_if_space(&mut self, buf_len: usize) -> Option<*mut LlmpMsg> {
        unsafe {
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
                map.shmem.id().as_str(),
                last_msg
            );

            let page_bytes = page.cast::<u8>();
            #[expect(clippy::cast_ptr_alignment)]
            let ret = page_bytes
                .add(LLMP_PAGE_HEADER_LEN + (*page).size_used)
                .cast::<LlmpMsg>();

            // Make sure the end of our msg is aligned.
            let msg_addr = ret as usize;
            let buf_len_padded = llmp_align(msg_addr + buf_len + size_of::<LlmpMsg>())
                - msg_addr
                - size_of::<LlmpMsg>();

            #[cfg(feature = "llmp_debug")]
            log::trace!(
                "{page:?} {:?} size_used={:x} buf_len_padded={:x} EOP_MSG_SIZE={:x} size_total={}",
                *page,
                (*page).size_used,
                buf_len_padded,
                EOP_MSG_SIZE,
                (*page).size_total
            );

            // For future allocs, keep track of the maximum (aligned) alloc size we used
            (*page).max_alloc_size = max(
                (*page).max_alloc_size,
                size_of::<LlmpMsg>() + buf_len_padded,
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

            /* We need to start with 1 for ids, as current message id is initialized
             * with 0... */
            (*ret).message_id = if last_msg.is_null() {
                MessageId((*page).current_msg_id.load(Ordering::Relaxed) + 1)
            } else if (*page).current_msg_id.load(Ordering::Relaxed) == (*last_msg).message_id.0 {
                MessageId((*last_msg).message_id.0 + 1)
            } else {
                /* Oops, wrong usage! */
                panic!(
                    "BUG: The current message never got committed using send! (page->current_msg_id {:?}, last_msg->message_id: {:?})",
                    &raw const (*page).current_msg_id,
                    (*last_msg).message_id
                );
            };

            (*ret).buf_len = buf_len as u64;
            (*ret).buf_len_padded = buf_len_padded as u64;
            (*page).size_used += size_of::<LlmpMsg>() + buf_len_padded;

            (*llmp_next_msg_ptr(ret)).tag = LLMP_TAG_UNSET;
            (*ret).tag = LLMP_TAG_UNINITIALIZED;

            self.has_unsent_message = true;

            Some(ret)
        }
    }

    /// Commit the message last allocated by [`Self::alloc_next`] to the queue.
    /// After commiting, the msg shall no longer be altered!
    /// It will be read by the consuming threads (`broker->clients` or `client->broker`)
    /// If `overwrite_client_id` is `false`, the message's `sender` won't be touched (for broker forwarding)
    #[inline(never)] // Not inlined to make cpu-level reodering (hopefully?) improbable
    unsafe fn send(&mut self, msg: *mut LlmpMsg, overwrite_client_id: bool) -> Result<(), Error> {
        unsafe {
            // log::info!("Sending msg {:?}", msg);

            assert!(
                !ptr::addr_eq(self.last_msg_sent, msg),
                "Message sent twice!"
            );
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

            let mid = (*page).current_msg_id.load(Ordering::Relaxed) + 1;
            (*msg).message_id.0 = mid;

            // Make sure all things have been written to the page, and commit the message to the page
            (*page)
                .current_msg_id
                .store((*msg).message_id.0, Ordering::Release);

            self.last_msg_sent = msg;
            self.has_unsent_message = false;

            log::debug!(
                "[{} - {:#x}] Send message with id {}",
                self.id.0,
                ptr::from_ref::<Self>(self) as u64,
                mid
            );

            Ok(())
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
}

/// Receiving end on a (unidirectional) sharedmap channel
#[derive(Debug)]
pub struct LlmpReceiver<SHM, SP> {
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
    current_recv_shmem: LlmpSharedMap<SHM>,
    /// Caches the highest msg id we've seen so far
    highest_msg_id: MessageId,
}

/// Receiving end of an llmp channel
impl<SHM, SP> LlmpReceiver<SHM, SP>
where
    SHM: ShMem,
    SP: ShMemProvider<ShMem = SHM>,
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

    /// Create a Receiver, reattaching to an existing sender map.
    /// It is essential, that the sender (or someone else) keeps a pointer to the `sender_shmem`
    /// else reattach will get a new, empty page, from the OS, or fail.
    pub fn on_existing_shmem(
        shmem_provider: SP,
        current_sender_shmem: SHM,
        last_msg_recvd_offset: Option<u64>,
    ) -> Result<Self, Error> {
        let mut current_recv_shmem = LlmpSharedMap::existing(current_sender_shmem);
        unsafe {
            if (*current_recv_shmem.page())
                .receivers_joined_count
                .load(Ordering::Acquire)
                == 0
            {
                current_recv_shmem.mark_safe_to_unmap();
            }
        }
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
        unsafe {
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
                Some(llmp_page_messages_mut_ptr(page))
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
                if !(*msg).in_shmem(&self.current_recv_shmem) {
                    return Err(Error::illegal_state(
                        "Unexpected message in map (out of map bounds) - buggy client or tampered shared map detected!",
                    ));
                }

                log::debug!(
                    "[{} - {:#x}] Received message with ID {}...",
                    self.id.0,
                    ptr::from_ref::<Self>(self) as u64,
                    (*msg).message_id.0
                );

                // Handle special, LLMP internal, messages.
                match (*msg).tag {
                    LLMP_TAG_UNSET => panic!(
                        "BUG: Read unallocated msg (tag was {:?} - msg header: {:?}",
                        LLMP_TAG_UNSET,
                        (*msg)
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

                        #[expect(clippy::cast_ptr_alignment)]
                        let pageinfo = llmp_msg_buf_mut_ptr(msg).cast::<LlmpPayloadSharedMapInfo>();

                        /* The pageinfo points to the map we're about to unmap.
                        Copy the contents first to be safe (probably fine in rust either way). */
                        let pageinfo_cpy = *pageinfo;

                        // Set last msg we received to null (as the map may no longer exist)
                        self.last_msg_recvd = ptr::null();
                        self.highest_msg_id = MessageId(0);

                        // Mark the old page save to remap.
                        LlmpPage::receiver_left(page);

                        // Map the new page. The old one should be unmapped by Drop
                        self.current_recv_shmem =
                            LlmpSharedMap::existing(self.shmem_provider.shmem_from_id_and_size(
                                ShMemId::from_array(&pageinfo_cpy.shm_str),
                                pageinfo_cpy.map_size,
                            )?);
                        let new_page = self.current_recv_shmem.page_mut();

                        // Mark the old page as save to remap (it's mapped by us, the receiver, now)
                        LlmpPage::receiver_joined(new_page);

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
            }
            Ok(ret)
        }
    }

    /// Blocks/spins until the next message gets posted to the page,
    /// then returns that message.
    /// # Safety
    /// Returns a raw ptr, on the recv map. Should be safe in general
    pub unsafe fn recv_blocking(&mut self) -> Result<*mut LlmpMsg, Error> {
        unsafe {
            let mut current_msg_id = MessageId(0);
            let mut page = self.current_recv_shmem.page_mut();
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
                    if let Some(msg) = self.recv()? {
                        return Ok(msg);
                    }
                    page = self.current_recv_shmem.page_mut();
                    current_msg_id = MessageId(0);
                }
                hint::spin_loop();
            }
        }
    }

    /// Returns the next message, tag, buf, if available, else None
    #[expect(clippy::type_complexity)]
    #[inline]
    pub fn recv_buf(&mut self) -> Result<Option<(ClientId, Tag, &[u8])>, Error> {
        if let Some((sender, tag, _flags, buf)) = self.recv_buf_with_flags()? {
            Ok(Some((sender, tag, buf)))
        } else {
            Ok(None)
        }
    }

    /// Receive the buffer, also reading the LLMP internal message flags
    #[expect(clippy::type_complexity)]
    #[inline]
    pub fn recv_buf_with_flags(&mut self) -> Result<Option<(ClientId, Tag, Flags, &[u8])>, Error> {
        // # Safety
        // No user-provided potentially unsafe parameters.
        unsafe {
            Ok(match self.recv()? {
                Some(msg) => Some((
                    (*msg).sender,
                    (*msg).tag,
                    (*msg).flags,
                    (*msg).try_as_slice(&self.current_recv_shmem)?,
                )),
                None => None,
            })
        }
    }

    /// Receive the buffer, also reading the LLMP internal message flags
    #[inline]
    pub fn recv_buf_blocking_with_flags(&mut self) -> Result<(ClientId, Tag, Flags, &[u8]), Error> {
        // # Safety
        // No user-provided potentially unsafe parameters.
        unsafe {
            let msg = self.recv_blocking()?;
            Ok((
                (*msg).sender,
                (*msg).tag,
                (*msg).flags,
                (*msg).try_as_slice(&self.current_recv_shmem)?,
            ))
        }
    }

    /// Returns the next sender, tag, buf, looping until it becomes available
    #[inline]
    pub fn recv_buf_blocking(&mut self) -> Result<(ClientId, Tag, &[u8]), Error> {
        // # Safety
        // No user-provided potentially unsafe parameters.
        unsafe {
            let msg = self.recv_blocking()?;
            Ok((
                (*msg).sender,
                (*msg).tag,
                (*msg).try_as_slice(&self.current_recv_shmem)?,
            ))
        }
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

/// Receiving end of an llmp channel
impl<SHM, SP> LlmpReceiver<SHM, SP>
where
    SHM: ShMem,
{
    /// Store the info to this receiver to env.
    /// A new client can reattach to it using [`LlmpReceiver::on_existing_from_env()`]
    ///
    /// # Safety
    /// Alters the env. Should only be called from a single thread.
    #[cfg(feature = "std")]
    pub unsafe fn to_env(&self, env_name: &str) -> Result<(), Error> {
        let current_out_shmem = &self.current_recv_shmem;
        unsafe {
            current_out_shmem.shmem.write_to_env(env_name)?;
        }
        unsafe { current_out_shmem.msg_to_env(self.last_msg_recvd, env_name) }
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
}

/// A page wrapper
#[derive(Debug)]
pub struct LlmpSharedMap<SHM> {
    /// Shmem containg the actual (unsafe) page,
    /// shared between one `LlmpSender` and one `LlmpReceiver`
    shmem: SHM,
    page: *mut LlmpPage,
    map_size: usize,
}

unsafe impl<SHM: Send> Send for LlmpSharedMap<SHM> {}
unsafe impl<SHM: Sync> Sync for LlmpSharedMap<SHM> {}

// TODO: May be obsolete
/// The page struct, placed on a shared mem instance.
/// A thin wrapper around a [`ShMem`] implementation, with `llmp`-specific functionality
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

        let map_size = new_shmem.len();
        let page = unsafe {
            llmp_page_init(&mut new_shmem, sender, false);
            shmem2page_mut(&mut new_shmem)
        };
        Self {
            shmem: new_shmem,
            page,
            map_size,
        }
    }

    /// Maps and wraps an existing
    pub fn existing(mut existing_shmem: SHM) -> Self {
        #[cfg(feature = "llmp_debug")]
        //{
        //#[cfg(debug_assertions)]
        //let bt = Backtrace::capture();
        //#[cfg(not(debug_assertions))]
        //let bt = "<n/a (release)>";
        log::info!(
            "LLMP_DEBUG: Using existing map {} with size {}",
            existing_shmem.id(),
            existing_shmem.len(),
            //bt
        );
        //}

        let map_size = existing_shmem.len();
        let page = unsafe { shmem2page_mut(&mut existing_shmem) };
        let ret = Self {
            shmem: existing_shmem,
            page,
            map_size,
        };
        unsafe {
            assert!(
                (*ret.page()).magic == PAGE_INITIALIZED_MAGIC,
                "Map was not priviously initialized at {:?}",
                ret.shmem
            );
            #[cfg(feature = "llmp_debug")]
            log::info!("PAGE: {:?}", *ret.page());
        }
        ret
    }

    /// Marks the containing page as `safe_to_unmap`.
    /// This indicates, that the page may safely be unmapped by the sender.
    #[inline]
    pub fn mark_safe_to_unmap(&mut self) {
        // # Safety
        // No user-provided potentially unsafe parameters.
        unsafe {
            LlmpPage::receiver_joined(self.page_mut());
        }
    }

    /// Get the unsafe ptr to this page, situated on the shared map
    /// # Safety
    /// The unsafe page pointer is obviously unsafe.
    #[inline]
    pub unsafe fn page_mut(&mut self) -> *mut LlmpPage {
        self.page
    }

    /// Get the unsafe ptr to this page, situated on the shared map
    /// # Safety
    /// The unsafe page pointer is obviously unsafe.
    #[inline]
    pub unsafe fn page(&self) -> *const LlmpPage {
        self.page.cast_const()
    }

    /// Gets the offset of a message on this here page.
    /// Will return [`crate::Error::illegal_argument`] error if msg is not on page.
    ///
    /// # Safety
    /// This dereferences msg, make sure to pass a proper pointer to it.
    #[expect(clippy::cast_sign_loss)]
    pub unsafe fn msg_to_offset(&self, msg: *const LlmpMsg) -> Result<u64, Error> {
        unsafe {
            let page = self.page();
            if llmp_msg_in_page(page, msg) {
                // Cast both sides to u8 arrays, get the offset, then cast the return isize to u64
                Ok(
                    (msg as *const u8).offset_from(llmp_page_messages_ptr(page) as *const u8)
                        as u64,
                )
            } else {
                Err(Error::illegal_argument(format!(
                    "Message (0x{:X}) not in page (0x{:X})",
                    page as u64, msg as u64
                )))
            }
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
            // TODO: Audit that the environment access only happens in single-threaded code.
            unsafe { env::set_var(format!("{map_env_name}_OFFSET"), _NULL_ENV_STR) };
        } else {
            // TODO: Audit that the environment access only happens in single-threaded code.
            unsafe {
                env::set_var(
                    format!("{map_env_name}_OFFSET"),
                    format!("{}", self.msg_to_offset(msg)?),
                );
            };
        }
        Ok(())
    }

    /// Gets this message from this page, at the indicated offset.
    /// Will return [`crate::Error::illegal_argument`] error if the offset is out of bounds.
    #[expect(clippy::cast_ptr_alignment)]
    pub fn msg_from_offset(&mut self, offset: u64) -> Result<*mut LlmpMsg, Error> {
        let page = unsafe { self.page_mut() };
        let page_size = self.map_size.saturating_sub(size_of::<LlmpPage>());
        let Some(offset) = usize::try_from(offset).ok().filter(|offset| {
            offset
                .checked_add(size_of::<LlmpMsg>())
                .is_some_and(|end| end <= page_size)
        }) else {
            return Err(Error::illegal_argument(format!(
                "Msg offset out of bounds (size: {page_size}, requested offset: {offset})"
            )));
        };
        unsafe { Ok((llmp_page_messages_mut_ptr(page) as *mut u8).add(offset) as *mut LlmpMsg) }
    }
}

/// The inner state of [`LlmpBroker`]
#[derive(Debug)]
pub struct LlmpBrokerInner<SHM, SP> {
    /// Broadcast map from broker to all clients
    llmp_out: LlmpSender<SHM, SP>,
    /// Users of Llmp can add message handlers in the broker.
    /// This allows us to intercept messages right in the broker.
    /// This keeps the out map clean.
    /// The backing values of `llmp_clients` [`ClientId`]s will always be sorted (but not gapless)
    /// Make sure to always increase `num_clients_seen` when pushing a new [`LlmpReceiver`] to  `llmp_clients`!
    llmp_clients: Vec<LlmpReceiver<SHM, SP>>,
    /// The own listeners we spawned via `launch_listener` or `crate_attach_to_tcp`.
    /// Listeners will be ignored for `exit_cleanly_after` and they are never considered to have timed out.
    listeners: Vec<ClientId>,
    /// The total amount of clients we had, historically, including those that disconnected, and our listeners.
    num_clients_seen: usize,
    /// Shared atomic view of `num_clients_seen` so background TCP listener threads do not hand out duplicate [`ClientId`]s.
    #[cfg(feature = "std")]
    num_clients_seen_atomic: Arc<AtomicUsize>,
    /// The amount of total clients that should have connected and (and disconnected)
    /// after which the broker loop should quit gracefully.
    pub exit_cleanly_after: Option<NonZeroUsize>,
    /// Clients that should be removed soon
    clients_to_remove: Vec<ClientId>,
    /// The `ShMemProvider` to use
    shmem_provider: SP,
}

/// The broker (node 0)
#[derive(Debug)]
pub struct LlmpBroker<HT, SHM, SP> {
    /// The broker
    inner: LlmpBrokerInner<SHM, SP>,
    /// Llmp hooks
    hooks: HT,
}

/// The trait for brokers.
pub trait Broker {
    /// Getter to `is_shutting_down`
    fn is_shutting_down(&self) -> bool;

    /// The hooks run for `on_timeout`
    fn on_timeout(&mut self) -> Result<(), Error>;

    /// The main thing the `broker` does
    fn broker_once(&mut self) -> Result<bool, Error>;

    /// Getter to `exit_after`
    fn exit_after(&self) -> Option<NonZeroUsize>;

    /// Setter for `exit_after`
    fn set_exit_after(&mut self, n_clients: NonZeroUsize);

    /// Getter to `has_clients`
    fn has_clients(&self) -> bool;

    /// Send the buffer out
    fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error>;

    /// Getter to `num_clients_seen`
    fn num_clients_seen(&self) -> usize;

    /// Getter to `nb_listeners`
    fn nb_listeners(&self) -> usize;
}

impl<HT, SHM, SP> Broker for LlmpBroker<HT, SHM, SP>
where
    HT: LlmpHookTuple<SHM, SP>,
    SHM: ShMem,
    SP: ShMemProvider<ShMem = SHM>,
{
    fn is_shutting_down(&self) -> bool {
        self.inner.is_shutting_down()
    }

    fn on_timeout(&mut self) -> Result<(), Error> {
        self.hooks.on_timeout_all()
    }

    fn broker_once(&mut self) -> Result<bool, Error> {
        self.broker_once()
    }

    fn exit_after(&self) -> Option<NonZeroUsize> {
        self.inner.exit_cleanly_after
    }
    fn set_exit_after(&mut self, n_clients: NonZeroUsize) {
        self.inner.set_exit_cleanly_after(n_clients);
    }

    fn has_clients(&self) -> bool {
        self.inner.has_clients()
    }

    fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        self.inner.llmp_out.send_buf(tag, buf)
    }

    fn num_clients_seen(&self) -> usize {
        self.inner.num_clients_seen
    }

    fn nb_listeners(&self) -> usize {
        self.inner.listeners.len()
    }
}

/// A set of brokers.
/// Limitation: the hooks must be the same.
#[cfg(feature = "std")]
#[derive(Default)]
pub struct Brokers {
    /// the brokers
    llmp_brokers: Vec<Box<dyn Broker>>,
}

#[cfg(feature = "std")]
impl Debug for Brokers {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Debug::fmt("Brokers", f)?;
        Ok(())
    }
}

/// A signal handler for the [`LlmpBroker`].
/// On unix, it handles signals
/// On Windows - control signals (e.g., CTRL+C)
#[cfg(any(unix, all(windows, feature = "std")))]
#[derive(Debug)]
pub struct LlmpShutdownSignalHandler {
    shutting_down: AtomicBool,
}

#[cfg(all(unix, feature = "alloc"))]
impl SignalHandler for LlmpShutdownSignalHandler {
    unsafe fn handle(
        &mut self,
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
    ) {
        self.shutting_down.store(true, Ordering::Release);
    }

    fn signals(&self) -> Vec<Signal> {
        vec![Signal::SigTerm, Signal::SigInterrupt, Signal::SigQuit]
    }
}

#[cfg(all(windows, feature = "std"))]
impl CtrlHandler for LlmpShutdownSignalHandler {
    fn handle(&mut self, ctrl_type: u32) -> bool {
        log::info!("LLMP: Received shutdown signal, ctrl_type {ctrl_type:?}");
        self.shutting_down.store(true, Ordering::Release);
        true
    }
}

/// Llmp hooks
pub trait LlmpHook<SHM, SP> {
    /// Hook called whenever a new message is received. It receives an llmp message as input, does
    /// something with it (read, transform, forward, etc...) and decides to discard it or not.
    fn on_new_message(
        &mut self,
        broker_inner: &mut LlmpBrokerInner<SHM, SP>,
        client_id: ClientId,
        msg_tag: &mut Tag,
        msg_flags: &mut Flags,
        msg: &mut [u8],
        new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
    ) -> Result<LlmpMsgHookResult, Error>;

    /// Hook called whenever there is a timeout.
    fn on_timeout(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// A tuple of Llmp hooks. They are evaluated sequentially, and returns if one decides to filter out the evaluated message.
pub trait LlmpHookTuple<SHM, SP> {
    /// Call all hook callbacks on new message.
    fn on_new_message_all(
        &mut self,
        inner: &mut LlmpBrokerInner<SHM, SP>,
        client_id: ClientId,
        msg_tag: &mut Tag,
        msg_flags: &mut Flags,
        msg: &mut [u8],
        new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
    ) -> Result<LlmpMsgHookResult, Error>;

    /// Call all hook callbacks on timeout.
    fn on_timeout_all(&mut self) -> Result<(), Error>;
}

impl<SHM, SP> LlmpHookTuple<SHM, SP> for () {
    fn on_new_message_all(
        &mut self,
        _inner: &mut LlmpBrokerInner<SHM, SP>,
        _client_id: ClientId,
        _msg_tag: &mut Tag,
        _msg_flags: &mut Flags,
        _msg: &mut [u8],
        _new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
    ) -> Result<LlmpMsgHookResult, Error> {
        Ok(LlmpMsgHookResult::ForwardToClients)
    }

    fn on_timeout_all(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl<Head, Tail, SHM, SP> LlmpHookTuple<SHM, SP> for (Head, Tail)
where
    Head: LlmpHook<SHM, SP>,
    Tail: LlmpHookTuple<SHM, SP>,
{
    fn on_new_message_all(
        &mut self,
        inner: &mut LlmpBrokerInner<SHM, SP>,
        client_id: ClientId,
        msg_tag: &mut Tag,
        msg_flags: &mut Flags,
        msg: &mut [u8],
        new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
    ) -> Result<LlmpMsgHookResult, Error> {
        match self
            .0
            .on_new_message(inner, client_id, msg_tag, msg_flags, msg, new_msgs)?
        {
            LlmpMsgHookResult::Handled => {
                // message handled, stop early
                Ok(LlmpMsgHookResult::Handled)
            }
            LlmpMsgHookResult::ForwardToClients => {
                // message should be forwarded, continue iterating
                self.1
                    .on_new_message_all(inner, client_id, msg_tag, msg_flags, msg, new_msgs)
            }
        }
    }

    fn on_timeout_all(&mut self) -> Result<(), Error> {
        self.0.on_timeout()?;
        self.1.on_timeout_all()
    }
}

impl<SHM, SP> LlmpBroker<(), SHM, SP> {
    /// Add hooks to a hookless [`LlmpBroker`].
    /// We do not support replacing hooks for now.
    pub fn add_hooks<HT>(self, hooks: HT) -> LlmpBroker<HT, SHM, SP>
    where
        HT: LlmpHookTuple<SHM, SP>,
    {
        LlmpBroker {
            inner: self.inner,
            hooks,
        }
    }
}

#[cfg(feature = "std")]
impl Brokers {
    /// The constructor
    #[must_use]
    pub fn new() -> Self {
        Self {
            llmp_brokers: Vec::new(),
        }
    }

    /// Add another broker
    pub fn add(&mut self, broker: Box<dyn Broker>) {
        self.llmp_brokers.push(broker);
    }

    #[cfg(any(all(unix, feature = "alloc", not(miri)), all(windows, feature = "std")))]
    fn setup_handlers() {
        #[cfg(all(unix, not(miri)))]
        if let Err(e) = unsafe { setup_signal_handler(&raw mut LLMP_SIGHANDLER_STATE) } {
            // We can live without a proper ctrl+c signal handler - Ignore.
            log::info!("Failed to setup signal handlers: {e}");
        } else {
            log::info!("Successfully setup signal handlers");
        }

        #[cfg(all(windows, feature = "std"))]
        if let Err(e) = unsafe { setup_ctrl_handler(&raw mut LLMP_SIGHANDLER_STATE) } {
            // We can live without a proper ctrl+c signal handler - Ignore.
            log::info!("Failed to setup control handlers: {e}");
        } else {
            log::info!(
                "{}: Broker successfully setup control handlers",
                std::process::id()
            );
        }
    }

    /// Loops until the last client quits the last broker,
    /// forwarding and handling all incoming messages from clients for each broker.
    /// Will call `on_timeout` roughly after `timeout`
    /// Panics on error.
    /// 5 millis of sleep can't hurt to keep busywait not at 100%
    #[cfg(feature = "std")]
    pub fn loop_with_timeouts(&mut self, timeout: Duration, sleep_time: Option<Duration>) {
        use no_std_time::current_milliseconds;

        #[cfg(any(all(unix, feature = "alloc", not(miri)), all(windows, feature = "std")))]
        Self::setup_handlers();

        let timeout = timeout.as_millis() as u64;
        let mut end_time = current_milliseconds() + timeout;

        loop {
            self.llmp_brokers.retain_mut(|broker| {
                if broker.is_shutting_down() {
                    broker.send_buf(LLMP_TAG_EXITING, &[]).expect(
                        "Error when shutting down broker: Could not send LLMP_TAG_EXITING msg.",
                    );

                    return false;
                }

                if current_milliseconds() > end_time {
                    broker
                        .on_timeout()
                        .expect("An error occurred in broker timeout. Exiting.");
                    end_time = current_milliseconds() + timeout;
                }

                if broker
                    .broker_once()
                    .expect("An error occurred when brokering. Exiting.")
                {
                    end_time = current_milliseconds() + timeout;
                }

                if let Some(exit_after_count) = broker.exit_after() {
                    // log::trace!(
                    //     "Clients connected: {} && > {} - {} >= {}",
                    //     self.has_clients(),
                    //     self.num_clients_seen,
                    //     self.listeners.len(),
                    //     exit_after_count
                    // );
                    if !broker.has_clients()
                        && (broker.num_clients_seen() - broker.nb_listeners())
                            >= exit_after_count.into()
                    {
                        // No more clients connected, and the amount of clients we were waiting for was previously connected.
                        // exit cleanly.
                        return false;
                    }
                }

                true
            });

            if self.llmp_brokers.is_empty() {
                break;
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
    }
}

impl<HT, SHM, SP> LlmpBroker<HT, SHM, SP>
where
    HT: LlmpHookTuple<SHM, SP>,
    SHM: ShMem,
    SP: ShMemProvider<ShMem = SHM>,
{
    /// Create and initialize a new [`LlmpBroker`], associated with some hooks.
    pub fn new(shmem_provider: SP, hooks: HT) -> Result<Self, Error> {
        Self::with_keep_pages(shmem_provider, hooks, true)
    }

    /// Create and initialize a new [`LlmpBroker`] telling if it has to keep pages forever
    pub fn with_keep_pages(
        shmem_provider: SP,
        hooks: HT,
        keep_pages_forever: bool,
    ) -> Result<Self, Error> {
        Ok(LlmpBroker {
            inner: LlmpBrokerInner::with_keep_pages(shmem_provider, keep_pages_forever)?,
            hooks,
        })
    }

    /// Create a new [`LlmpBroker`] attaching to a TCP port
    #[cfg(feature = "std")]
    pub fn create_attach_to_tcp(shmem_provider: SP, hooks: HT, port: u16) -> Result<Self, Error> {
        log::info!("LlmpBroker: creating on port {port}");
        let inner = LlmpBrokerInner::create_attach_to_tcp(shmem_provider, port)?;
        log::info!("LlmpBroker: created inner on port {port}");
        Ok(LlmpBroker { inner, hooks })
    }

    /// Create a new [`LlmpBroker`] attaching to a TCP port and telling if it has to keep pages forever
    #[cfg(feature = "std")]
    pub fn with_keep_pages_attach_to_tcp(
        shmem_provider: SP,
        hooks: HT,
        port: u16,
        keep_pages_forever: bool,
    ) -> Result<Self, Error> {
        Ok(LlmpBroker {
            inner: LlmpBrokerInner::with_keep_pages_attach_to_tcp(
                shmem_provider,
                port,
                keep_pages_forever,
            )?,
            hooks,
        })
    }

    /// Get the inner state of the broker
    pub fn inner(&self) -> &LlmpBrokerInner<SHM, SP> {
        &self.inner
    }

    /// Get the inner mutable state of the broker
    pub fn inner_mut(&mut self) -> &mut LlmpBrokerInner<SHM, SP> {
        &mut self.inner
    }

    /// Loops unitl the last client quit,
    /// forwarding and handling all incoming messages from clients.
    /// 5 millis of sleep can't hurt to keep busywait not at 100%
    /// On std, if you need to run code even if no update got sent, use `Self::loop_with_timeout` (needs the `std` feature).
    pub fn loop_forever(&mut self, sleep_time: Option<Duration>) {
        #[cfg(any(all(unix, feature = "alloc", not(miri)), all(windows, feature = "std")))]
        Self::setup_handlers();

        while !self.inner.is_shutting_down() {
            self.broker_once()
                .expect("An error occurred when brokering. Exiting.");

            if let Some(exit_after_count) = self.inner.exit_cleanly_after
                && !self.inner.has_clients()
                && (self.inner.num_clients_seen - self.inner.listeners.len())
                    >= exit_after_count.into()
            {
                // No more clients connected, and the amount of clients we were waiting for was previously connected.
                // exit cleanly.
                break;
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
        self.inner
            .llmp_out
            .send_buf(LLMP_TAG_EXITING, &[])
            .expect("Error when shutting down broker: Could not send LLMP_TAG_EXITING msg.");
    }

    /// Loops until the last client quits,
    /// forwarding and handling all incoming messages from clients.
    /// Will call `on_timeout` roughly after `timeout`
    /// Panics on error.
    /// 5 millis of sleep can't hurt to keep busywait not at 100%
    #[cfg(feature = "std")]
    pub fn loop_with_timeouts(&mut self, timeout: Duration, sleep_time: Option<Duration>) {
        use no_std_time::current_milliseconds;

        #[cfg(any(all(unix, feature = "alloc", not(miri)), all(windows, feature = "std")))]
        Self::setup_handlers();

        let timeout = timeout.as_millis() as u64;
        let mut end_time = current_milliseconds() + timeout;

        while !self.inner.is_shutting_down() {
            if current_milliseconds() > end_time {
                self.hooks
                    .on_timeout_all()
                    .expect("An error occurred in broker timeout. Exiting.");
                end_time = current_milliseconds() + timeout;
            }

            if self
                .broker_once()
                .expect("An error occurred when brokering. Exiting.")
            {
                end_time = current_milliseconds() + timeout;
            }

            if let Some(exit_after_count) = self.inner.exit_cleanly_after {
                // log::trace!(
                //     "Clients connected: {} && > {} - {} >= {}",
                //     self.has_clients(),
                //     self.num_clients_seen,
                //     self.listeners.len(),
                //     exit_after_count
                // );
                if !self.inner.has_clients()
                    && (self.inner.num_clients_seen - self.inner.listeners.len())
                        >= exit_after_count.into()
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
        self.inner
            .llmp_out
            .send_buf(LLMP_TAG_EXITING, &[])
            .expect("Error when shutting down broker: Could not send LLMP_TAG_EXITING msg.");
    }

    /// The broker walks all pages and looks for changes, then broadcasts them on
    /// its own shared page, once.
    #[inline]
    pub fn broker_once(&mut self) -> Result<bool, Error> {
        let mut new_messages = false;
        for i in 0..self.inner.llmp_clients.len() {
            let client_id = self.inner.llmp_clients[i].id;
            match unsafe { self.handle_new_msgs(client_id) } {
                Ok(has_messages) => {
                    new_messages |= has_messages;
                }
                Err(Error::ShuttingDown) => {
                    self.inner.clients_to_remove.push(client_id);
                }
                Err(err) => return Err(err),
            }
        }

        let possible_remove = self.inner.clients_to_remove.len();
        if possible_remove > 0 {
            self.inner.clients_to_remove.sort_unstable();
            self.inner.clients_to_remove.dedup();
            log::trace!("Removing {:#?}", self.inner.clients_to_remove);
            // rev() to make it works
            // commit the change to llmp_clients
            for idx in (0..self.inner.llmp_clients.len()).rev() {
                let client_id = self.inner.llmp_clients[idx].id;
                if self.inner.clients_to_remove.contains(&client_id) {
                    log::info!("Client {client_id:#?} wants to exit. Removing.");
                    self.inner.llmp_clients.remove(idx);
                }
            }
            // log::trace!("{:#?}", self.llmp_clients);
        }

        self.inner.clients_to_remove.clear();
        Ok(new_messages)
    }

    /// Broker broadcast to its own page for all others to read
    /// Returns `true` if new messages were broker-ed
    /// It is supposed that the message is never unmapped.
    #[inline]
    #[expect(clippy::cast_ptr_alignment)]
    #[expect(clippy::too_many_lines)]
    unsafe fn handle_new_msgs(&mut self, client_id: ClientId) -> Result<bool, Error> {
        unsafe {
            let mut new_messages = false;

            // TODO: We could memcpy a range of pending messages, instead of one by one.
            loop {
                // log::trace!("{:#?}", self.llmp_clients);
                let msg = {
                    let pos = if (client_id.0 as usize) < self.inner.llmp_clients.len()
                        && self.inner.llmp_clients[client_id.0 as usize].id == client_id
                    {
                        // Fast path when no client before this one was removed
                        client_id.0 as usize
                    } else {
                        self.inner
                            .llmp_clients
                            .binary_search_by_key(&client_id, |x| x.id)
                            .unwrap_or_else(|_| {
                                panic!(
                                "Fatal error, client ID {client_id:?} not found in llmp_clients."
                            )
                            })
                    };
                    let client = &mut self.inner.llmp_clients[pos];
                    match client.recv()? {
                        None => {
                            // We're done handling this client
                            #[cfg(feature = "std")]
                            if new_messages {
                                // set the recv time
                                // We don't do that in recv() to keep calls to `current_time` to a minimum.
                                self.inner.llmp_clients[pos].last_msg_time = current_time();
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
                        return Err(Error::unknown(format!(
                            "The broker was too slow to handle messages of client {client_id:?} in time, so it quit. Either the client sent messages too fast, or we (the broker) got stuck!"
                        )));
                    }
                    LLMP_TAG_CLIENT_EXIT => {
                        let msg_buf_len_padded = (*msg).buf_len_padded;
                        if (*msg).buf_len < size_of::<LlmpClientExitInfo>() as u64 {
                            log::info!(
                                "Ignoring broken CLIENT_EXIT msg due to incorrect size. Expected {} but got {}",
                                msg_buf_len_padded,
                                size_of::<LlmpClientExitInfo>()
                            );
                            #[cfg(not(feature = "std"))]
                            return Err(Error::unknown(format!(
                                "Broken CLIENT_EXIT msg with incorrect size received. Expected {} but got {}",
                                msg_buf_len_padded,
                                size_of::<LlmpClientExitInfo>()
                            )));
                        }
                        let exitinfo =
                            (llmp_msg_buf_mut_ptr(msg) as *mut LlmpClientExitInfo).read_unaligned();
                        let client_id = ClientId(exitinfo.client_id);
                        log::info!(
                            "Client exit message received!, we are removing clients whose client_group_id is {client_id:#?}"
                        );

                        self.inner.clients_to_remove.push(client_id);
                    }
                    LLMP_TAG_NEW_SHM_CLIENT => {
                        /* This client informs us about yet another new client
                        add it to the list! Also, no need to forward this msg. */
                        let msg_buf_len_padded = (*msg).buf_len_padded;
                        if (*msg).buf_len < size_of::<LlmpPayloadSharedMapInfo>() as u64 {
                            log::info!(
                                "Ignoring broken CLIENT_ADDED msg due to incorrect size. Expected {} but got {}",
                                msg_buf_len_padded,
                                size_of::<LlmpPayloadSharedMapInfo>()
                            );
                            #[cfg(not(feature = "std"))]
                            return Err(Error::unknown(format!(
                                "Broken CLIENT_ADDED msg with incorrect size received. Expected {} but got {}",
                                msg_buf_len_padded,
                                size_of::<LlmpPayloadSharedMapInfo>()
                            )));
                        }
                        let pageinfo = llmp_msg_buf_mut_ptr(msg) as *mut LlmpPayloadSharedMapInfo;
                        match self.inner.shmem_provider.shmem_from_id_and_size(
                            ShMemId::from_array(&(*pageinfo).shm_str),
                            (*pageinfo).map_size,
                        ) {
                            Ok(new_shmem) => {
                                let mut new_page = LlmpSharedMap::existing(new_shmem);
                                new_page.mark_safe_to_unmap();

                                let _new_client = self.inner.add_client(LlmpReceiver {
                                    id: ClientId(0), // will be auto-filled
                                    current_recv_shmem: new_page,
                                    last_msg_recvd: ptr::null_mut(),
                                    shmem_provider: self.inner.shmem_provider.clone(),
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
                        }
                    }
                    // handle all other messages
                    _ => {
                        let pos = if (client_id.0 as usize) < self.inner.llmp_clients.len()
                            && self.inner.llmp_clients[client_id.0 as usize].id == client_id
                        {
                            // Fast path when no client before this one was removed
                            client_id.0 as usize
                        } else {
                            self.inner
                            .llmp_clients
                            .binary_search_by_key(&client_id, |x| x.id)
                            .unwrap_or_else(|_| panic!("Fatal error, client ID {client_id:?} not found in llmp_clients."))
                        };

                        let map = &raw mut self.inner.llmp_clients[pos].current_recv_shmem;
                        let msg_buf = (*msg).try_as_slice_mut(&mut *map)?;

                        // The message is not specifically for use. Let the user handle it, then forward it to the clients, if necessary.
                        let mut new_msgs: Vec<(Tag, Flags, Vec<u8>)> = Vec::new();
                        if let LlmpMsgHookResult::ForwardToClients = self.hooks.on_new_message_all(
                            &mut self.inner,
                            client_id,
                            &mut (*msg).tag,
                            &mut (*msg).flags,
                            msg_buf,
                            &mut new_msgs,
                        )? {
                            self.inner.forward_msg(msg)?;
                        }

                        log::debug!("New msg vector: {}", new_msgs.len());
                        for (new_msg_tag, new_msg_flag, new_msg) in new_msgs {
                            self.inner.llmp_out.send_buf_with_flags(
                                new_msg_tag,
                                new_msg_flag,
                                new_msg.as_ref(),
                            )?;
                        }
                    }
                }
            }
        }
    }

    #[cfg(any(all(unix, feature = "alloc", not(miri)), all(windows, feature = "std")))]
    fn setup_handlers() {
        #[cfg(all(unix, not(miri)))]
        if let Err(e) = unsafe { setup_signal_handler(&raw mut LLMP_SIGHANDLER_STATE) } {
            // We can live without a proper ctrl+c signal handler - Ignore.
            log::info!("Failed to setup signal handlers: {e}");
        } else {
            log::info!("Successfully setup signal handlers");
        }

        #[cfg(all(windows, feature = "std"))]
        if let Err(e) = unsafe { setup_ctrl_handler(&raw mut LLMP_SIGHANDLER_STATE) } {
            // We can live without a proper ctrl+c signal handler - Ignore.
            log::info!("Failed to setup control handlers: {e}");
        } else {
            log::info!(
                "{}: Broker successfully setup control handlers",
                std::process::id()
            );
        }
    }
}

/// The broker forwards all messages to its own bus-like broadcast map.
/// It may intercept messages passing through.
impl<SHM, SP> LlmpBrokerInner<SHM, SP>
where
    SHM: ShMem,
    SP: ShMemProvider<ShMem = SHM>,
{
    /// Create and initialize a new [`LlmpBrokerInner`], associated with some hooks.
    pub fn new(shmem_provider: SP) -> Result<Self, Error> {
        Self::with_keep_pages(shmem_provider, true)
    }

    /// Create and initialize a new [`LlmpBrokerInner`] telling if it has to keep pages forever
    pub fn with_keep_pages(
        mut shmem_provider: SP,
        keep_pages_forever: bool,
    ) -> Result<Self, Error> {
        Ok(LlmpBrokerInner {
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
            clients_to_remove: Vec::new(),
            listeners: vec![],
            exit_cleanly_after: None,
            num_clients_seen: 0,
            #[cfg(feature = "std")]
            num_clients_seen_atomic: Arc::new(AtomicUsize::new(0)),
            shmem_provider,
        })
    }

    /// Gets the [`ClientId`] the next client attaching to this broker will get.
    /// In its current implementation, the inner value of the next [`ClientId`]
    /// is equal to `self.num_clients_seen`.
    /// Calling `peek_next_client_id` multiple times (without adding a client) will yield the same value.
    #[must_use]
    #[inline]
    pub fn peek_next_client_id(&self) -> ClientId {
        ClientId(
            self.num_clients_seen
                .try_into()
                .expect("More than u32::MAX clients!"),
        )
    }

    /// Create a new [`LlmpBrokerInner`] attaching to a TCP port
    #[cfg(feature = "std")]
    pub fn create_attach_to_tcp(shmem_provider: SP, port: u16) -> Result<Self, Error> {
        Self::with_keep_pages_attach_to_tcp(shmem_provider, port, true)
    }

    /// Create a new [`LlmpBrokerInner`] attaching to a TCP port and telling if it has to keep pages forever
    #[cfg(feature = "std")]
    pub fn with_keep_pages_attach_to_tcp(
        shmem_provider: SP,
        port: u16,
        keep_pages_forever: bool,
    ) -> Result<Self, Error> {
        match tcp_bind(port) {
            Ok(listener) => {
                let mut broker =
                    LlmpBrokerInner::with_keep_pages(shmem_provider, keep_pages_forever)?;
                let _listener_thread = broker.launch_listener(Listener::Tcp(listener))?;
                Ok(broker)
            }
            Err(e) => Err(e),
        }
    }

    /// Set this broker to exit after at least `n_clients` clients attached and all client exited.
    /// Will ignore the own listener thread, if `create_attach_to_tcp`
    ///
    /// So, if the `n_client` value is `2`, the broker will not exit after client 1 connected and disconnected,
    /// but it will quit after client 2 connected and disconnected.
    pub fn set_exit_cleanly_after(&mut self, n_clients: NonZeroUsize) {
        self.exit_cleanly_after = Some(n_clients);
    }

    /// Add a client to this broker.
    /// Will set an appropriate [`ClientId`] before pushing the client to the internal vec.
    /// Will increase `num_clients_seen`.
    /// The backing values of `llmp_clients` [`ClientId`]s will always be sorted (but not gapless)
    /// returns the [`ClientId`] of the new client.
    pub fn add_client(&mut self, mut client_receiver: LlmpReceiver<SHM, SP>) -> ClientId {
        let id = self.peek_next_client_id();
        client_receiver.id = id;
        self.llmp_clients.push(client_receiver);
        self.num_clients_seen += 1;
        #[cfg(feature = "std")]
        self.num_clients_seen_atomic
            .store(self.num_clients_seen, Ordering::Release);
        id
    }

    /// Allocate the next message on the outgoing map
    unsafe fn alloc_next(&mut self, buf_len: usize) -> Result<*mut LlmpMsg, Error> {
        self.llmp_out.alloc_next(buf_len)
    }

    /// Registers a new client for the given sharedmap str and size.
    /// Returns the [`ClientId`] of the newly registered client.
    pub fn register_client(&mut self, mut client_page: LlmpSharedMap<SHM>) -> ClientId {
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
                ));
            }
        }

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
        unsafe {
            let out: *mut LlmpMsg = self.alloc_next((*msg).buf_len as usize)?;

            /* Copy over the whole message.
            If we should need zero copy, we could instead post a link to the
            original msg with the map_id and offset. */
            let actual_size = (*out).buf_len_padded;
            let complete_size = (*msg).buf_len as usize + size_of::<LlmpMsg>();
            (msg as *const u8).copy_to_nonoverlapping(out as *mut u8, complete_size);
            (*out).buf_len_padded = actual_size;
            /* We need to replace the message ID with our own */
            if let Err(e) = self.llmp_out.send(out, false) {
                panic!("Error sending msg: {e:?}");
            }
            self.llmp_out.last_msg_sent = out;
            Ok(())
        }
    }

    /// Internal function, returns true when shuttdown is requested by a `SIGINT` signal
    #[inline]
    #[cfg(any(unix, all(windows, feature = "std")))]
    #[expect(clippy::unused_self)]
    fn is_shutting_down(&self) -> bool {
        // # Safety
        // No user-provided potentially unsafe parameters.
        // Atomic load.
        unsafe {
            let state_ptr = &raw const LLMP_SIGHANDLER_STATE;
            (*state_ptr).shutting_down.load(Ordering::Acquire)
        }
    }

    /// Always returns true on platforms, where no shutdown signal handlers are supported
    #[inline]
    #[cfg(not(any(unix, all(windows, feature = "std"))))]
    #[expect(clippy::unused_self)]
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
    /// Upon receiving this message, the broker should map the announced page and start tracking it for new messages.
    #[cfg(feature = "std")]
    fn announce_new_client(
        sender: &mut LlmpSender<SHM, SP>,
        shmem_description: &ShMemDescription,
    ) -> Result<(), Error> {
        unsafe {
            let msg = sender
                .alloc_next(size_of::<LlmpPayloadSharedMapInfo>())
                .expect("Could not allocate a new message in shared map.");
            (*msg).tag = LLMP_TAG_NEW_SHM_CLIENT;
            #[expect(clippy::cast_ptr_alignment)]
            let pageinfo = llmp_msg_buf_mut_ptr(msg) as *mut LlmpPayloadSharedMapInfo;
            (*pageinfo).shm_str = *shmem_description.id.as_array();
            (*pageinfo).map_size = shmem_description.size;
            sender.send(msg, true)
        }
    }

    /// Tell the broker to disconnect this client from it.
    #[cfg(feature = "std")]
    fn announce_client_exit(sender: &mut LlmpSender<SHM, SP>, client_id: u32) -> Result<(), Error> {
        // # Safety
        // No user-provided potentially unsafe parameters.
        unsafe {
            let msg = sender
                .alloc_next(size_of::<LlmpClientExitInfo>())
                .expect("Could not allocate a new message in shared map.");
            (*msg).tag = LLMP_TAG_CLIENT_EXIT;
            let client_id_offset = offset_of!(LlmpClientExitInfo, client_id);
            write_unaligned(
                llmp_msg_buf_mut_ptr(msg).add(client_id_offset) as _,
                client_id,
            );
            sender.send(msg, true)
        }
    }

    /// For broker to broker connections:
    /// Launches a proxy thread.
    /// It will read outgoing messages from the given broker map (and handle EOP by mapping a new page).
    /// This function returns the [`ShMemDescription`] the client uses to place incoming messages.
    /// The thread exits, when the remote broker disconnects.
    #[cfg(feature = "std")]
    #[expect(clippy::too_many_lines)]
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

            #[cfg(feature = "llmp_debug")]
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
                                log::info!(
                                    "Got error {e} while trying to forward a message to broker {peer_address}, exiting thread"
                                );
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
                        if let Error::OsError(e, ..) = e
                            && e.kind() == io::ErrorKind::UnexpectedEof
                        {
                            log::info!("Broker {peer_address} seems to have disconnected, exiting");
                            return;
                        }

                        #[cfg(feature = "llmp_debug")]
                        log::info!("Received no input, timeout or closed. Looping back up :)");
                    }
                }
            }
        });

        let ret = recv.recv().map_err(|err| {
            Error::unknown(format!(
                "Error launching background thread for b2b communcation: {err:?}"
            ))
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
        num_clients_seen_atomic: &AtomicUsize,
        sender: &mut LlmpSender<SHM, SP>,
        broker_shmem_description: &ShMemDescription,
    ) {
        let seen = u32::try_from(num_clients_seen_atomic.load(Ordering::Acquire))
            .expect("More than u32::MAX clients!");
        current_client_id.0 = max(current_client_id.0, seen);
        match request {
            TcpRequest::ClientQuit { client_id } => {
                // todo search the ancestor_id and remove it.
                match Self::announce_client_exit(sender, client_id.0) {
                    Ok(()) => (),
                    Err(e) => log::info!("Error announcing client exit: {e:?}"),
                }
            }
            TcpRequest::LocalClientHello { shmem_description } => {
                match Self::announce_new_client(sender, shmem_description) {
                    Ok(()) => (),
                    Err(e) => log::info!("Error forwarding client on map: {e:?}"),
                }

                if let Err(e) = send_tcp_msg(
                    &mut stream,
                    &TcpResponse::LocalClientAccepted {
                        client_id: *current_client_id,
                    },
                ) {
                    log::info!("An error occurred sending via tcp {e}");
                }
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
                    }
                    current_client_id.0 += 1;
                }
            }
        }
    }

    #[cfg(feature = "std")]
    /// Launches a thread using a listener socket, on which new clients may connect to this broker
    pub fn launch_listener(&mut self, listener: Listener) -> Result<thread::JoinHandle<()>, Error> {
        // Later in the execution, after the initial map filled up,
        // the current broadcast map will point to a different map.
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
        let num_clients_seen_atomic = Arc::clone(&self.num_clients_seen_atomic);

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
                    Ok(ListenerStream::Tcp(mut stream, addr)) => {
                        log::info!(
                            "New connection: {:?}/{:?}",
                            addr,
                            stream.peer_addr().unwrap_or(addr)
                        );

                        // Send initial information, without anyone asking.
                        // This makes it a tiny bit easier to map the broker map for new Clients.
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

                        // log::info!("{:#?}", buf);
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
                            &num_clients_seen_atomic,
                            &mut tcp_incoming_sender,
                            &broker_shmem_description,
                        );
                    }
                    Ok(ListenerStream::Empty()) => {}
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(err) => {
                        log::error!(
                            "Fatal accept error on listener: {err:?}, terminating listener thread."
                        );
                        break;
                    }
                }
            }
        });

        self.listeners.push(listener_id);

        Ok(ret)
    }
}

/// A restorable client description
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct LlmpClientDescription {
    /// Description of the sender
    sender: LlmpDescription,
    /// Description of the receiver
    receiver: LlmpDescription,
}

/// Client side of LLMP
#[derive(Debug)]
pub struct LlmpClient<SHM, SP> {
    /// Outgoing channel to the broker
    sender: LlmpSender<SHM, SP>,
    /// Incoming (broker) broadcast map
    receiver: LlmpReceiver<SHM, SP>,
}

/// `n` clients connect to a broker. They share an outgoing map with the broker,
/// and get incoming messages from the shared broker bus
impl<SHM, SP> LlmpClient<SHM, SP>
where
    SHM: ShMem,
    SP: ShMemProvider<ShMem = SHM>,
{
    /// Creates a new [`LlmpClient`]
    pub fn new(
        mut shmem_provider: SP,
        initial_broker_shmem: LlmpSharedMap<SHM>,
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
    pub fn new_p2p(mut shmem_provider: SP, sender_id: ClientId) -> Result<Self, Error> {
        let sender = LlmpSender::new(shmem_provider.clone(), sender_id, false)?;
        let shmem = shmem_provider.clone_ref(&sender.out_shmems[0].shmem)?;
        let receiver = LlmpReceiver::on_existing_shmem(shmem_provider, shmem, None)?;
        Ok(Self { sender, receiver })
    }

    /// Reattach to a vacant client map.
    /// It is essential, that the broker (or someone else) kept a pointer to the `out_shmem`
    /// else reattach will get a new, empty page, from the OS, or fail
    pub fn on_existing_shmem(
        shmem_provider: SP,
        current_out_shmem: SHM,
        last_msg_sent_offset: Option<u64>,
        current_broker_shmem: SHM,
        last_msg_recvd_offset: Option<u64>,
    ) -> Result<Self, Error> {
        Ok(Self {
            receiver: LlmpReceiver::on_existing_shmem(
                shmem_provider.clone(),
                current_broker_shmem,
                last_msg_recvd_offset,
            )?,
            sender: LlmpSender::on_existing_shmem(
                shmem_provider,
                current_out_shmem,
                last_msg_sent_offset,
            )?,
        })
    }

    /// Recreate this client from a previous [`LlmpClient::to_env`]
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

    /// Allocates a message of the given size, tags it, and sends it off.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        self.sender.send_buf(tag, buf)
    }

    /// Send a `buf` with the given `flags`.
    pub fn send_buf_with_flags(&mut self, tag: Tag, flags: Flags, buf: &[u8]) -> Result<(), Error> {
        self.sender.send_buf_with_flags(tag, flags, buf)
    }

    /// A client receives a broadcast message.
    /// Returns null if no message is availiable
    /// # Safety
    /// Should be save, unless the internal state is corrupt. Returns raw ptr.
    #[inline]
    pub unsafe fn recv(&mut self) -> Result<Option<*mut LlmpMsg>, Error> {
        unsafe { self.receiver.recv() }
    }

    /// A client blocks/spins until the next message gets posted to the page,
    /// then returns that message.
    /// # Safety
    /// Should be save, unless the internal state is corrupt. Returns raw ptr.
    #[inline]
    pub unsafe fn recv_blocking(&mut self) -> Result<*mut LlmpMsg, Error> {
        unsafe { self.receiver.recv_blocking() }
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
    #[expect(clippy::type_complexity)]
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
    #[expect(clippy::type_complexity)]
    pub fn recv_buf_with_flags(&mut self) -> Result<Option<(ClientId, Tag, Flags, &[u8])>, Error> {
        self.receiver.recv_buf_with_flags()
    }

    /// Receive a `buf` from the broker, including the `flags` used during transmission.
    pub fn recv_buf_blocking_with_flags(&mut self) -> Result<(ClientId, Tag, Flags, &[u8]), Error> {
        self.receiver.recv_buf_blocking_with_flags()
    }

    #[cfg(feature = "std")]
    /// Creates a new [`LlmpClient`], reading the map id and len from env
    pub fn create_using_env(mut shmem_provider: SP, env_var: &str) -> Result<Self, Error> {
        let map = LlmpSharedMap::existing(shmem_provider.existing_from_env(env_var)?);
        let client_id = unsafe { (*map.page()).sender_id };
        Self::new(shmem_provider, map, client_id)
    }

    #[cfg(feature = "std")]
    /// Create a [`LlmpClient`], getting the ID from a given port, then also tell the restarter's ID so we ask to be removed later
    /// This is called when, for the first time, the restarter attaches to this process.
    pub fn create_attach_to_tcp(mut shmem_provider: SP, port: u16) -> Result<Self, Error> {
        let mut stream = match TcpStream::connect((IP_LOCALHOST, port)) {
            Ok(stream) => stream,
            Err(e) => {
                match e.kind() {
                    io::ErrorKind::ConnectionRefused => {
                        //connection refused. loop till the broker is up
                        loop {
                            if let Ok(stream) = TcpStream::connect((IP_LOCALHOST, port)) {
                                break stream;
                            }

                            log::debug!("Connection Refused. Retrying...");

                            #[cfg(feature = "std")]
                            thread::sleep(Duration::from_millis(50));
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

        // Now sender contains 1 shmem, that must be shared back with the broker.
        let client_hello_req = TcpRequest::LocalClientHello {
            shmem_description: ret.sender.out_shmems.first().unwrap().shmem.description(),
        };
        send_tcp_msg(&mut stream, &client_hello_req)?;

        // The broker accepted the client, and sent back an ID.
        let TcpResponse::LocalClientAccepted {
            client_id: client_sender_id,
        } = recv_tcp_msg(&mut stream)?.try_into()?
        else {
            return Err(Error::illegal_state(
                "Unexpected Response from Broker".to_string(),
            ));
        };

        // Set our ID to the one the broker sent us.
        // This is mainly so we can filter out our own msgs later.
        ret.sender.id = client_sender_id;
        // Also set the sender on our initial llmp map correctly.
        unsafe {
            (*ret.sender.out_shmems.first_mut().unwrap().page_mut()).sender_id = client_sender_id;
        }

        Ok(ret)
    }
}

impl<SHM, SP> LlmpClient<SHM, SP>
where
    SHM: ShMem,
{
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
        unsafe {
            self.sender.mark_safe_to_unmap();
        }
    }

    /// Commits a msg to the client's out map
    /// # Safety
    /// Needs to be called with a proper msg pointer
    pub unsafe fn send(&mut self, msg: *mut LlmpMsg) -> Result<(), Error> {
        unsafe { self.sender.send(msg, true) }
    }

    /// Write the current state to env.
    /// A new client can attach to exactly the same state by calling [`LlmpClient::on_existing_shmem()`].
    ///
    /// # Safety
    /// Writes to env variables and may only be done single-threaded.
    #[cfg(feature = "std")]
    pub unsafe fn to_env(&self, env_name: &str) -> Result<(), Error> {
        unsafe {
            self.sender.to_env(&format!("{env_name}_SENDER"))?;
            self.receiver.to_env(&format!("{env_name}_RECEIVER"))
        }
    }

    /// Describe this client in a way that it can be recreated, for example after crash
    pub fn describe(&self) -> Result<LlmpClientDescription, Error> {
        Ok(LlmpClientDescription {
            sender: self.sender.describe()?,
            receiver: self.receiver.describe()?,
        })
    }
}

impl<SHM, SP> LlmpClient<SHM, SP> {
    /// Outgoing channel to the broker
    #[must_use]
    pub fn sender(&self) -> &LlmpSender<SHM, SP> {
        &self.sender
    }

    /// Outgoing channel to the broker (mut)
    #[must_use]
    pub fn sender_mut(&mut self) -> &mut LlmpSender<SHM, SP> {
        &mut self.sender
    }

    /// Incoming (broker) broadcast map
    #[must_use]
    pub fn receiver(&self) -> &LlmpReceiver<SHM, SP> {
        &self.receiver
    }

    /// Incoming (broker) broadcast map (mut)
    #[must_use]
    pub fn receiver_mut(&mut self) -> &mut LlmpReceiver<SHM, SP> {
        &mut self.receiver
    }
}

#[cfg(test)]
#[cfg(all(unix, feature = "std", not(target_os = "haiku")))]
mod tests {

    use alloc::vec;
    use core::time::Duration;
    use std::thread::sleep;

    use serial_test::serial;
    use shmem_providers::{ShMem, ShMemProvider, StdShMemProvider};

    use super::{
        ClientId, LlmpClient,
        LlmpConnection::{self, IsBroker, IsClient},
        LlmpSharedMap, Tag,
    };

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_llmp_connection() {
        let shmem_provider = StdShMemProvider::new().unwrap();
        let mut broker = match LlmpConnection::on_port(shmem_provider.clone(), 21337).unwrap() {
            IsClient { client: _ } => panic!("Could not bind to port as broker"),
            IsBroker { broker } => broker,
        };

        // Add the first client (2nd, actually, because of the tcp listener client)
        let mut client = match LlmpConnection::on_port(shmem_provider.clone(), 21337).unwrap() {
            IsBroker { broker: _ } => panic!("Second connect should be a client!"),
            IsClient { client } => client,
        };

        // Give the (background) tcp thread a few millis to post the message
        sleep(Duration::from_millis(100));
        broker.broker_once().unwrap();

        let tag: Tag = Tag(0x1337);
        let arr: [u8; 1] = [1_u8];
        // Send stuff
        client.send_buf(tag, &arr).unwrap();

        // # Safety
        // Test only. Should run one instance.
        unsafe {
            client.to_env("_ENV_TEST").unwrap();
        }
        #[cfg(all(feature = "llmp_debug", feature = "std"))]
        log::info!("{:?}", std::env::vars());

        for (key, value) in std::env::vars_os() {
            log::info!("{key:?}: {value:?}");
        }

        /* recreate the client from env, check if it still works */
        client = LlmpClient::on_existing_from_env(shmem_provider, "_ENV_TEST").unwrap();

        client.send_buf(tag, &arr).unwrap();

        // Forward stuff to clients
        broker.broker_once().unwrap();
        let (_sender_id, tag2, arr2) = client.recv_buf_blocking().unwrap();
        assert_eq!(tag, tag2);
        assert_eq!(arr[0], arr2[0]);

        // We want at least the tcp and sender clients.
        assert_eq!(broker.inner.llmp_clients.len(), 2);
    }

    #[test]
    #[serial]
    #[should_panic(expected = "Map was not priviously initialized at")]
    fn test_llmp_assert_uninitialized_map() {
        #[cfg(not(miri))]
        let mut shmem_provider = StdShMemProvider::new().unwrap();
        #[cfg(miri)]
        let mut shmem_provider = shmem_providers::NopShMemProvider::new().unwrap();
        let shmem = shmem_provider.new_shmem(1024).unwrap();
        let map = LlmpSharedMap::existing(shmem);
        drop(map);
    }

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_llmp_on_existing_shmem() {
        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut broker = match LlmpConnection::on_port(shmem_provider.clone(), 1338).unwrap() {
            IsClient { client: _ } => panic!("Could not bind to port as broker"),
            IsBroker { broker } => broker,
        };

        let client = match LlmpConnection::on_port(shmem_provider.clone(), 1338).unwrap() {
            IsBroker { broker: _ } => panic!("Second connect should be a client!"),
            IsClient { client } => client,
        };

        sleep(Duration::from_millis(100));
        broker.broker_once().unwrap();

        let out_shmem = shmem_provider
            .clone_ref(&client.sender().out_shmems.first().unwrap().shmem)
            .unwrap();

        let broker_shmem = shmem_provider
            .clone_ref(&client.receiver().current_recv_shmem.shmem)
            .unwrap();

        let mut reattached_client =
            LlmpClient::on_existing_shmem(shmem_provider, out_shmem, None, broker_shmem, None)
                .unwrap();

        let tag = Tag(0x4242);
        let payload = [0x42_u8];
        reattached_client.send_buf(tag, &payload).unwrap();

        broker.broker_once().unwrap();
        let (_sender_id, tag2, payload2) = reattached_client.recv_buf_blocking().unwrap();
        assert_eq!(tag, tag2);
        assert_eq!(payload[0], payload2[0]);
    }

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_llmp_in_shmem_bounds_edge_cases() {
        use core::mem::size_of;

        use super::{LlmpMsg, LlmpPage};

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let map_size = 1024;
        let shmem = shmem_provider.new_shmem(map_size).unwrap();
        let map = LlmpSharedMap::new(ClientId(0), shmem);

        let page_ptr = unsafe { map.page().cast_mut().cast::<u8>() };

        // Valid message header right after page header
        #[expect(clippy::cast_ptr_alignment)]
        let valid_msg_ptr = unsafe { page_ptr.add(size_of::<LlmpPage>()).cast::<LlmpMsg>() };
        let valid_msg = unsafe { &mut *valid_msg_ptr };
        valid_msg.buf_len_padded = 64;

        assert!(valid_msg.in_shmem(&map));

        // Message that extends exactly up to map_size
        let exact_fit_len = map_size - size_of::<LlmpPage>() - size_of::<LlmpMsg>();
        valid_msg.buf_len_padded = exact_fit_len as u64;
        assert!(valid_msg.in_shmem(&map));

        // Message that extends 1 byte past map_size (must be REJECTED)
        valid_msg.buf_len_padded = (exact_fit_len + 1) as u64;
        assert!(!valid_msg.in_shmem(&map));

        // Malicious huge buf_len_padded causing usize overflow (must be REJECTED)
        valid_msg.buf_len_padded = u64::MAX;
        assert!(!valid_msg.in_shmem(&map));

        // Header positioned inside the page header region (must be REJECTED)
        #[expect(clippy::cast_ptr_alignment)]
        let invalid_header_ptr = unsafe { page_ptr.add(16).cast::<LlmpMsg>() };
        let invalid_msg = unsafe { &mut *invalid_header_ptr };
        invalid_msg.buf_len_padded = 16;
        assert!(!invalid_msg.in_shmem(&map));

        // buf_len exceeding buf_len_padded (must be REJECTED)
        valid_msg.buf_len_padded = 64;
        valid_msg.buf_len = 65;
        assert!(!valid_msg.in_shmem(&map));
        valid_msg.buf_len = 64;
        assert!(valid_msg.in_shmem(&map));
    }

    #[test]
    fn test_llmp_in_shmem_miri() {
        use core::mem::size_of;

        use shmem_providers::NopShMemProvider;

        use super::{BrokerId, Flags, LlmpMsg, LlmpPage, MessageId};

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let map_size = 1024;
        let shmem = shmem_provider.new_shmem(map_size).unwrap();
        let mut map = LlmpSharedMap::new(ClientId(0), shmem);

        let page_ptr = unsafe { map.page_mut().cast::<u8>() };

        // 1. Valid message header right after page header (offset = 48)
        #[expect(clippy::cast_ptr_alignment)]
        let valid_msg_ptr = unsafe { page_ptr.add(size_of::<LlmpPage>()).cast::<LlmpMsg>() };
        unsafe {
            (*valid_msg_ptr).buf_len = 64;
            (*valid_msg_ptr).buf_len_padded = 64;
        };
        assert!(unsafe { (*valid_msg_ptr).in_shmem(&map) });

        // buf_len exceeding buf_len_padded (must be REJECTED)
        unsafe { (*valid_msg_ptr).buf_len = 65 };
        assert!(!unsafe { (*valid_msg_ptr).in_shmem(&map) });
        unsafe { (*valid_msg_ptr).buf_len = 64 };

        // 2. Message that extends exactly up to map_size
        let exact_fit_len = map_size - size_of::<LlmpPage>() - size_of::<LlmpMsg>();
        unsafe {
            (*valid_msg_ptr).buf_len = exact_fit_len as u64;
            (*valid_msg_ptr).buf_len_padded = exact_fit_len as u64;
        };
        assert!(unsafe { (*valid_msg_ptr).in_shmem(&map) });

        // 3. Message that extends 1 byte past map_size (must be REJECTED)
        unsafe { (*valid_msg_ptr).buf_len_padded = (exact_fit_len + 1) as u64 };
        assert!(!unsafe { (*valid_msg_ptr).in_shmem(&map) });

        // 4. Malicious huge buf_len_padded causing u64/usize overflow (must be REJECTED)
        unsafe { (*valid_msg_ptr).buf_len_padded = u64::MAX };
        assert!(!unsafe { (*valid_msg_ptr).in_shmem(&map) });

        unsafe { (*valid_msg_ptr).buf_len_padded = (usize::MAX - size_of::<LlmpMsg>()) as u64 };
        assert!(!unsafe { (*valid_msg_ptr).in_shmem(&map) });

        // 5. Header positioned inside page header region (offset = 16, must be REJECTED)
        #[expect(clippy::cast_ptr_alignment)]
        let invalid_header_ptr = unsafe { page_ptr.add(16).cast::<LlmpMsg>() };
        unsafe { (*invalid_header_ptr).buf_len_padded = 16 };
        assert!(!unsafe { (*invalid_header_ptr).in_shmem(&map) });

        // 6. Address before page_start (must be REJECTED)
        let before_page_dummy = LlmpMsg {
            tag: Tag(0),
            sender: ClientId(0),
            broker: BrokerId(0),
            flags: Flags(0),
            message_id: MessageId(0),
            buf_len: 10,
            buf_len_padded: 16,
            buf: [],
        };
        assert!(!before_page_dummy.in_shmem(&map));
    }

    #[test]
    fn test_llmp_msg_as_slice_provenance() {
        use core::mem::size_of;

        use shmem_providers::NopShMemProvider;

        use super::{LlmpMsg, LlmpPage};

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let map_size = 1024;
        let shmem = shmem_provider.new_shmem(map_size).unwrap();
        let mut map = LlmpSharedMap::new(ClientId(0), shmem);

        let page_ptr = unsafe { map.page_mut().cast::<u8>() };
        #[expect(clippy::cast_ptr_alignment)]
        let valid_msg_ptr = unsafe { page_ptr.add(size_of::<LlmpPage>()).cast::<LlmpMsg>() };
        unsafe {
            (*valid_msg_ptr).tag = Tag(1);
            (*valid_msg_ptr).buf_len = 16;
            (*valid_msg_ptr).buf_len_padded = 16;
            let slice = LlmpMsg::as_slice_mut_raw(valid_msg_ptr);
            slice[0] = 42;
            assert_eq!(slice[0], 42);
            let slice_ref = LlmpMsg::as_slice_raw(valid_msg_ptr);
            assert_eq!(slice_ref[0], 42);
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_llmp_page_concurrent_receivers() {
        use core::sync::atomic::Ordering;
        use std::thread;

        use shmem_providers::NopShMemProvider;

        use super::{LlmpPage, llmp_page_init, shmem2page_mut};

        #[derive(Copy, Clone)]
        struct SendPagePtr(*mut LlmpPage);
        unsafe impl Send for SendPagePtr {}
        unsafe impl Sync for SendPagePtr {}

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let mut shmem = shmem_provider.new_shmem(1024).unwrap();
        unsafe {
            llmp_page_init(&mut shmem, ClientId(0), false);
        }

        let page_ptr = SendPagePtr(unsafe { shmem2page_mut(&mut shmem) });
        let mut handles = vec![];

        for _ in 0..10 {
            handles.push(thread::spawn(move || {
                let page_ptr = page_ptr;
                let page = page_ptr.0.cast_const();
                for _ in 0..100 {
                    unsafe {
                        LlmpPage::receiver_joined(page);
                        LlmpPage::receiver_left(page);
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let page = unsafe { &*page_ptr.0 };
        assert_eq!(page.receivers_joined_count.load(Ordering::Relaxed), 1000);
        assert_eq!(page.receivers_left_count.load(Ordering::Relaxed), 1000);
    }

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_llmp_resume_from_offset() {
        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut broker = match LlmpConnection::on_port(shmem_provider.clone(), 1339).unwrap() {
            IsClient { client: _ } => panic!("Could not bind to port as broker"),
            IsBroker { broker } => broker,
        };

        let mut client = match LlmpConnection::on_port(shmem_provider.clone(), 1339).unwrap() {
            IsBroker { broker: _ } => panic!("Second connect should be a client!"),
            IsClient { client } => client,
        };

        broker.broker_once().unwrap();

        let tag1 = Tag(0x1111);
        let payload1 = [0x11_u8];
        client.send_buf(tag1, &payload1).unwrap();
        broker.broker_once().unwrap();
        let (_sender_id, _tag, _recv_payload) = client.recv_buf_blocking().unwrap();

        let last_sent_msg = client.sender().last_msg_sent;
        let last_sent_offset = if last_sent_msg.is_null() {
            None
        } else {
            unsafe {
                client
                    .sender()
                    .out_shmems
                    .first()
                    .unwrap()
                    .msg_to_offset(last_sent_msg)
                    .ok()
            }
        };

        let last_recvd_msg = client.receiver().last_msg_recvd;
        let last_recvd_offset = if last_recvd_msg.is_null() {
            None
        } else {
            unsafe {
                client
                    .receiver()
                    .current_recv_shmem
                    .msg_to_offset(last_recvd_msg)
                    .ok()
            }
        };

        let out_shmem = shmem_provider
            .clone_ref(&client.sender().out_shmems.first().unwrap().shmem)
            .unwrap();

        let broker_shmem = shmem_provider
            .clone_ref(&client.receiver().current_recv_shmem.shmem)
            .unwrap();

        let mut resumed_client = LlmpClient::on_existing_shmem(
            shmem_provider,
            out_shmem,
            last_sent_offset,
            broker_shmem,
            last_recvd_offset,
        )
        .unwrap();

        let tag2 = Tag(0x2222);
        let payload2 = [0x22_u8];
        resumed_client.send_buf(tag2, &payload2).unwrap();

        broker.broker_once().unwrap();
        let (_sender_id2, recvd_tag2, recvd_payload2) = resumed_client.recv_buf_blocking().unwrap();
        assert_eq!(tag2, recvd_tag2);
        assert_eq!(payload2[0], recvd_payload2[0]);
    }

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_llmp_eop_page_rollover() {
        use crate::{LlmpReceiver, LlmpSender};

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(shmem_provider.clone(), ClientId(0), false).unwrap();
        let sender_shmem = shmem_provider
            .clone_ref(&sender.out_shmems.first().unwrap().shmem)
            .unwrap();
        let mut receiver =
            LlmpReceiver::on_existing_shmem(shmem_provider, sender_shmem, None).unwrap();

        let msg_tag = Tag(0xABC);
        let large_buf = vec![0x42_u8; 120];

        for i in 0..5 {
            let mut buf = large_buf.clone();
            buf[0] = i;
            sender.send_buf(msg_tag, &buf).unwrap();
        }

        for i in 0..5 {
            let msg = unsafe { receiver.recv() }
                .unwrap()
                .expect("Should receive message");
            let slice = unsafe { (*msg).as_slice_unsafe() };
            assert_eq!(slice[0], i);
            assert_eq!(unsafe { (*msg).tag }, msg_tag);
        }
    }

    /// Regression test 1 & 9: Miri verifies no sub-object provenance UB in `send_buf`
    /// and `recv()` / `msg_to_offset` / `msg_from_offset`.
    #[test]
    fn test_proof_provenance_send_recv_miri() {
        use shmem_providers::NopShMemProvider;

        use crate::LlmpSender;

        let shmem_provider = NopShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(shmem_provider, ClientId(1), true).unwrap();
        sender.send_buf(Tag(0x1337), &[1, 2, 3, 4]).unwrap();
        let last_msg = sender.last_msg_sent;
        let offset = unsafe { sender.out_shmems[0].msg_to_offset(last_msg).unwrap() };
        let roundtrip_msg = sender.out_shmems[0].msg_from_offset(offset).unwrap();
        assert_eq!(roundtrip_msg.cast_const(), last_msg);
        let slice = unsafe {
            (*roundtrip_msg)
                .try_as_slice(&sender.out_shmems[0])
                .unwrap()
        };
        assert_eq!(slice, &[1, 2, 3, 4]);
    }

    /// Regression test 1a (Stacked Borrows in `LlmpSharedMap::page` / `safe_to_unmap`):
    /// Accessing atomic fields (`receivers_joined_count`, `receivers_left_count`, `current_msg_id`)
    /// via `map.page()` preserves `SharedReadWrite` provenance under Miri.
    #[test]
    fn test_proof_safe_to_unmap_shared_read_only_retag_miri() {
        use shmem_providers::NopShMemProvider;

        use crate::LlmpSender;

        let shmem_provider = NopShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(shmem_provider, ClientId(0), false).unwrap();
        assert!(!sender.safe_to_unmap());
        unsafe {
            sender.mark_safe_to_unmap();
        }
        assert!(sender.safe_to_unmap());
    }

    /// Regression test 1b (Memory Ordering & Raw-Pointer Atomic Projection):
    /// Verifies (1) no `&LlmpPage` retag read race when `LlmpPage::receiver_joined(page_ptr)` runs
    /// concurrently with sender writes to non-atomic `size_used`/`max_alloc_size`, and
    /// (2) C11/Rust `Release`/`Acquire` synchronization between `LlmpPage::receiver_left(page_ptr)`
    /// and `new_or_unused_shmem()`.
    #[test]
    fn test_proof_page_reuse_relaxed_ordering_data_race_miri() {
        use core::{mem::size_of, sync::atomic::Ordering};
        use std::thread;

        use shmem_providers::NopShMemProvider;

        use crate::{LlmpMsg, LlmpPage, llmp_page_init, shmem2page_mut};

        #[derive(Copy, Clone)]
        struct SendPagePtr(*mut LlmpPage);
        unsafe impl Send for SendPagePtr {}
        unsafe impl Sync for SendPagePtr {}

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let mut shmem = shmem_provider.new_shmem(1024).unwrap();
        let page_ptr = unsafe {
            llmp_page_init(&mut shmem, ClientId(0), false);
            SendPagePtr(shmem2page_mut(&mut shmem))
        };

        thread::scope(|s| {
            // Receiver thread: calls `receiver_joined(page_ptr)` while sender mutates `size_used`,
            // then leaves with `receiver_left(page_ptr)` (Release).
            s.spawn(move || unsafe {
                let page_ptr = page_ptr;
                let page_ptr = page_ptr.0.cast_const();
                LlmpPage::receiver_joined(page_ptr);
                #[expect(clippy::cast_ptr_alignment)]
                let first_msg = (page_ptr as *const u8)
                    .add(size_of::<LlmpPage>())
                    .cast::<LlmpMsg>();
                assert_eq!((*first_msg).tag, super::LLMP_TAG_UNSET);
                LlmpPage::receiver_left(page_ptr);
            });

            // Sender thread: concurrently mutates non-atomic `size_used` / `max_alloc_size` while
            // receiver joins, then waits for `receivers_joined_count == receivers_left_count` (Acquire)
            // before re-initializing `size_total`.
            s.spawn(move || unsafe {
                let page_ptr = page_ptr;
                let page_ptr = page_ptr.0;
                (*page_ptr).size_used = 64;
                (*page_ptr).max_alloc_size = 64;
                loop {
                    let joined = (*page_ptr).receivers_joined_count.load(Ordering::Acquire);
                    let left = (*page_ptr).receivers_left_count.load(Ordering::Acquire);
                    if joined > 0 && joined == left {
                        break;
                    }
                    core::hint::spin_loop();
                }
                (*page_ptr).size_total = 1024 - size_of::<LlmpPage>();
                #[expect(clippy::cast_ptr_alignment)]
                let first_msg = (page_ptr as *mut u8)
                    .add(size_of::<LlmpPage>())
                    .cast::<LlmpMsg>();
                (*first_msg).tag = super::LLMP_TAG_UNSET;
            });
        });
    }

    /// Regression test 8: `LLMP_SIGHANDLER_STATE.shutting_down` (`AtomicBool`) has no data race
    /// when accessed concurrently by signal handler and `is_shutting_down()`.
    #[test]
    fn test_proof_sighandler_data_race_miri() {
        use core::sync::atomic::Ordering;
        use std::thread;

        use shmem_providers::NopShMemProvider;
        use tuple_list::tuple_list;

        use crate::{LLMP_SIGHANDLER_STATE, LlmpBroker};

        thread::scope(|s| {
            s.spawn(|| unsafe {
                let state_ptr = &raw const LLMP_SIGHANDLER_STATE;
                (*state_ptr).shutting_down.store(true, Ordering::Release);
            });
            s.spawn(|| {
                let shmem_provider = NopShMemProvider::new().unwrap();
                let broker = LlmpBroker::new(shmem_provider, tuple_list!()).unwrap();
                let _ = broker.inner().is_shutting_down();
            });
        });
        unsafe {
            let state_ptr = &raw const LLMP_SIGHANDLER_STATE;
            (*state_ptr).shutting_down.store(false, Ordering::Release);
        }
    }

    /// Regression test 11b: `llmp_next_msg_ptr_checked` returns `Err` without
    /// integer underflow or OOB pointer arithmetic when `alloc_size > map_size`.
    #[test]
    fn test_proof_next_msg_ptr_checked_underflow() {
        use core::mem::size_of;

        use shmem_providers::NopShMemProvider;

        use crate::{LlmpMsg, LlmpPage, llmp_next_msg_ptr_checked};

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let map_size = 1024;
        let shmem = shmem_provider.new_shmem(map_size).unwrap();
        let mut map = LlmpSharedMap::new(ClientId(0), shmem);

        unsafe {
            let page_bytes = map.page_mut().cast::<u8>();
            #[expect(clippy::cast_ptr_alignment)]
            let first_msg = page_bytes.add(size_of::<LlmpPage>()).cast::<LlmpMsg>();
            assert!(llmp_next_msg_ptr_checked(&mut map, first_msg, map_size + 1).is_err());

            (*first_msg).buf_len_padded = u64::MAX;
            assert!(llmp_next_msg_ptr_checked(&mut map, first_msg, 16).is_err());
        }
    }

    /// Regression test 12: `LlmpMsg::try_as_slice` binds the returned slice's lifetime to
    /// `map: &LlmpSharedMap<SHM>` and derives full-page provenance from `map`.
    #[test]
    fn test_proof_try_as_slice_dangling_lifetime_miri() {
        use core::mem::size_of;

        use shmem_providers::NopShMemProvider;

        use crate::{LlmpMsg, LlmpPage};

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let shmem = shmem_provider.new_shmem(1024).unwrap();
        let mut map = LlmpSharedMap::new(ClientId(0), shmem);

        let msg_ref: &LlmpMsg = unsafe {
            let page_bytes = map.page_mut().cast::<u8>();
            #[expect(clippy::cast_ptr_alignment)]
            let msg_ptr = page_bytes.add(size_of::<LlmpPage>()).cast::<LlmpMsg>();
            (*msg_ptr).buf_len = 8;
            (*msg_ptr).buf_len_padded = 16;
            &*msg_ptr
        };

        let valid_slice: &[u8] = msg_ref.try_as_slice(&map).unwrap();
        assert_eq!(valid_slice.len(), 8);
        assert_eq!(valid_slice[0], 0);
        drop(map);
    }

    /// Regression test 17b: `LlmpClient::on_existing_shmem` takes ownership of `current_broker_shmem`
    /// directly without cloning and dropping it.
    #[test]
    fn test_proof_client_on_existing_shmem_clones_and_drops_broker_shmem() {
        use shmem_providers::NopShMemProvider;

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let out_map = LlmpSharedMap::new(ClientId(1), shmem_provider.new_shmem(1024).unwrap());
        let broker_map = LlmpSharedMap::new(ClientId(0), shmem_provider.new_shmem(1024).unwrap());

        let _client = LlmpClient::on_existing_shmem(
            shmem_provider,
            out_map.shmem,
            None,
            broker_map.shmem,
            None,
        )
        .unwrap();
    }

    /// Regression test 2: `LlmpReceiver::recv_blocking` transitions across an `EOP` page rollover
    /// and waits for the first message on the new page instead of panicking with NULL.
    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_proof_recv_blocking_panics_on_eop() {
        use std::thread;

        use crate::{LlmpReceiver, LlmpSender};

        let shmem_provider = StdShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(shmem_provider, ClientId(0), true).unwrap();
        let sender_desc = sender.out_shmems.first().unwrap().shmem.description();

        unsafe {
            sender.handle_out_eop().unwrap();
        }

        let handle = thread::spawn(move || unsafe {
            let mut shmem_provider_bg = StdShMemProvider::new().unwrap();
            let sender_shmem = shmem_provider_bg
                .shmem_from_description(sender_desc)
                .unwrap();
            let mut receiver =
                LlmpReceiver::on_existing_shmem(shmem_provider_bg, sender_shmem, None).unwrap();
            let msg = receiver.recv_blocking().unwrap();
            assert!(!msg.is_null());
            assert_eq!((*msg).tag, Tag(0x7777));
        });

        sleep(Duration::from_millis(20));
        sender.send_buf(Tag(0x7777), &[0x99]).unwrap();
        handle.join().unwrap();
    }

    /// Regression test 3: Real EOP page rollover on `LlmpSender` + `LlmpReceiver::on_existing_shmem`
    /// succeeds across arbitrarily many page rollovers without `LLMP_SLOW_RECEIVER_PANIC`.
    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_proof_real_eop_page_rollover_panics_due_to_unjoined_initial_page() {
        use crate::{LLMP_CFG_INITIAL_MAP_SIZE, LlmpReceiver, LlmpSender};

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(shmem_provider.clone(), ClientId(0), false).unwrap();
        let sender_shmem = shmem_provider
            .clone_ref(&sender.out_shmems.first().unwrap().shmem)
            .unwrap();
        let mut receiver =
            LlmpReceiver::on_existing_shmem(shmem_provider, sender_shmem, None).unwrap();

        let msg_tag = Tag(0xABC);
        let mut buf_size = (LLMP_CFG_INITIAL_MAP_SIZE / 2) + 1024;
        for _ in 0..6 {
            let buf = vec![0x42_u8; buf_size];
            sender.send_buf(msg_tag, &buf).unwrap();
            let (_sender, tag, recvd) = receiver
                .recv_buf()
                .unwrap()
                .expect("Receiver is 100% caught up");
            assert_eq!(tag, msg_tag);
            assert_eq!(recvd.len(), buf_size);
            buf_size *= 2;
        }
    }

    /// Regression test 4: `LlmpBrokerInner::forward_msg` copies only `(*msg).buf_len + size_of::<LlmpMsg>()`
    /// bytes and never reads past the end of `msg` into the next message slot on the client's page.
    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_proof_forward_msg_reads_past_client_msg_into_next_msg() {
        use alloc::vec::Vec;
        use core::mem::size_of;

        use tuple_list::tuple_list;

        use crate::{
            ClientId, Flags, LlmpBroker, LlmpBrokerInner, LlmpHook, LlmpMsg, LlmpMsgHookResult,
            llmp_next_msg_ptr,
        };

        #[derive(Debug)]
        struct DropFirstMsgHook;
        impl<SHM, SP> LlmpHook<SHM, SP> for DropFirstMsgHook {
            fn on_new_message(
                &mut self,
                _broker_inner: &mut LlmpBrokerInner<SHM, SP>,
                _client_id: ClientId,
                msg_tag: &mut Tag,
                _msg_flags: &mut Flags,
                _msg: &mut [u8],
                _new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
            ) -> Result<LlmpMsgHookResult, libafl_core::Error> {
                if *msg_tag == Tag(0x1) {
                    Ok(LlmpMsgHookResult::Handled)
                } else {
                    Ok(LlmpMsgHookResult::ForwardToClients)
                }
            }
        }

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut broker =
            LlmpBroker::new(shmem_provider.clone(), tuple_list!(DropFirstMsgHook)).unwrap();
        let broker_map = LlmpSharedMap::existing(
            shmem_provider
                .clone_ref(&broker.inner().llmp_out.out_shmems[0].shmem)
                .unwrap(),
        );
        let mut client = LlmpClient::new(shmem_provider.clone(), broker_map, ClientId(1)).unwrap();
        let client_map = LlmpSharedMap::existing(
            shmem_provider
                .clone_ref(&client.sender().out_shmems[0].shmem)
                .unwrap(),
        );
        broker.inner_mut().register_client(client_map);

        client.send_buf(Tag(0x1), &[0xAA]).unwrap();
        client.send_buf(Tag(0x2), &[0xBB]).unwrap();

        unsafe {
            let msg2_ptr = client.sender().last_msg_sent;
            assert_eq!((*msg2_ptr).buf_len, 1);
            assert_eq!((*msg2_ptr).buf_len_padded, 24);
            let msg3_ptr = llmp_next_msg_ptr(msg2_ptr).cast::<u8>();
            core::ptr::write_bytes(msg3_ptr, 0xFE, 16);
        }

        broker.broker_once().unwrap();

        unsafe {
            let forwarded_ptr: *const LlmpMsg = broker.inner().llmp_out.last_msg_sent;
            assert_eq!((*forwarded_ptr).buf_len, 1);
            assert_eq!((*forwarded_ptr).buf_len_padded, 40);
            let padding_tail = core::slice::from_raw_parts(
                (forwarded_ptr as *const u8).add(size_of::<LlmpMsg>() + 24),
                16,
            );
            assert_ne!(padding_tail, &[0xFE_u8; 16]);
        }
    }

    /// Regression test 5: `prune_old_pages` does not overwrite `(*page0).magic = PAGE_DEINITIALIZED_MAGIC`
    /// while `receivers_left_count == 0` (the receiver is still on `page0`).
    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_proof_prune_old_pages_deinitializes_page_while_receiver_still_active() {
        use crate::{LLMP_CFG_INITIAL_MAP_SIZE, LlmpReceiver, LlmpSender};

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(shmem_provider.clone(), ClientId(0), false).unwrap();
        let page0_shmem = shmem_provider
            .clone_ref(&sender.out_shmems.first().unwrap().shmem)
            .unwrap();
        let receiver =
            LlmpReceiver::on_existing_shmem(shmem_provider.clone(), page0_shmem, None).unwrap();

        let msg_tag = Tag(0xABC);
        let buf1 = vec![0x42_u8; (LLMP_CFG_INITIAL_MAP_SIZE / 2) + 1024];
        sender.send_buf(msg_tag, &buf1).unwrap();
        sender.send_buf(msg_tag, &buf1).unwrap();
        let buf2 = vec![0x42_u8; LLMP_CFG_INITIAL_MAP_SIZE + 2048];
        sender.send_buf(msg_tag, &buf2).unwrap();
        sender.send_buf(msg_tag, &buf2).unwrap();

        let desc = receiver.describe().unwrap();
        let _reattached =
            LlmpReceiver::on_existing_from_description(shmem_provider, &desc).unwrap();
    }

    /// Regression test 6: `prune_old_pages` panics cleanly with slow-receiver message instead of
    /// recursing infinitely (stack overflow) when `self.out_shmems.len() > LLMP_CFG_MAX_PENDING_UNREAD_PAGES`
    /// and the current page is full.
    #[test]
    #[should_panic(
        expected = "The receiver/broker could not process our sent llmp messages in time"
    )]
    fn test_proof_prune_old_pages_infinite_recursion_stack_overflow() {
        use shmem_providers::NopShMemProvider;

        use crate::{EOP_MSG_SIZE, LLMP_CFG_MAX_PENDING_UNREAD_PAGES, LlmpSender};

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(shmem_provider, ClientId(0), false).unwrap();
        sender.out_shmems.clear();
        for _ in 0..=LLMP_CFG_MAX_PENDING_UNREAD_PAGES {
            sender.out_shmems.push(LlmpSharedMap::new(
                ClientId(0),
                shmem_provider.new_shmem(1024).unwrap(),
            ));
        }
        unsafe {
            let last_page = sender.out_shmems.last_mut().unwrap().page_mut();
            (*last_page).size_used = (*last_page).size_total - EOP_MSG_SIZE;
            let _ = sender.alloc_next(16);
        }
    }

    /// Regression test 7: Calling `launch_tcp_listener_on` followed by `register_client` (as `connect_b2b` does)
    /// synchronizes `num_clients_seen_atomic` so the TCP listener assigns `ClientId(2)` matching the broker.
    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_proof_client_id_collision_between_tcp_listener_and_b2b() {
        use tuple_list::tuple_list;

        use crate::LlmpBroker;

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut broker = LlmpBroker::new(shmem_provider.clone(), tuple_list!()).unwrap();
        let port = 24681;
        broker.inner_mut().launch_tcp_listener_on(port).unwrap();

        let b2b_map = LlmpSharedMap::new(ClientId(1), shmem_provider.new_shmem(4096).unwrap());
        let b2b_id = broker.inner_mut().register_client(b2b_map);
        assert_eq!(b2b_id, ClientId(1));

        let tcp_client = LlmpClient::create_attach_to_tcp(shmem_provider, port).unwrap();
        sleep(Duration::from_millis(50));
        broker.broker_once().unwrap();

        let broker_assigned_id = broker.inner().llmp_clients.last().unwrap().id;
        assert_eq!(tcp_client.sender().id(), ClientId(2));
        assert_eq!(broker_assigned_id, ClientId(2));
        assert_eq!(tcp_client.sender().id(), broker_assigned_id);
    }

    /// Regression test 10: `llmp_msg_in_page` rejects offsets inside the `LlmpPage` header (`1..48`)
    /// and accepts valid message offsets in the last 48 bytes of the page (`[map_size - 48 .. map_size)`).
    #[test]
    fn test_proof_llmp_msg_in_page_bounds_bug() {
        use core::mem::size_of;

        use shmem_providers::NopShMemProvider;

        use crate::{LlmpMsg, LlmpPage, llmp_msg_in_page};

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let map_size = 1024;
        let shmem = shmem_provider.new_shmem(map_size).unwrap();
        let map = LlmpSharedMap::new(ClientId(0), shmem);

        unsafe {
            let page = map.page();
            let page_bytes = page.cast::<u8>();

            #[expect(clippy::cast_ptr_alignment)]
            let inside_header = page_bytes.add(16).cast::<LlmpMsg>();
            assert!(!(*inside_header).in_shmem(&map));
            assert!(!llmp_msg_in_page(page, inside_header));

            #[expect(clippy::cast_ptr_alignment)]
            let valid_tail_msg = page_bytes
                .add(map_size - size_of::<LlmpPage>())
                .cast::<LlmpMsg>()
                .cast_mut();
            (*valid_tail_msg).buf_len = 8;
            (*valid_tail_msg).buf_len_padded = 8;
            assert!((*valid_tail_msg).in_shmem(&map));
            assert!(llmp_msg_in_page(page, valid_tail_msg));
        }
    }

    /// Regression test 11: `msg_from_offset` rejects `offset == page_size` (and any offset where
    /// `offset + size_of::<LlmpMsg>() > page_size`).
    #[test]
    fn test_proof_msg_from_offset_allows_one_past_end() {
        use core::mem::size_of;

        use shmem_providers::NopShMemProvider;

        use crate::{LlmpMsg, LlmpPage};

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let map_size = 1024;
        let shmem = shmem_provider.new_shmem(map_size).unwrap();
        let mut map = LlmpSharedMap::new(ClientId(0), shmem);

        let page_size = (map_size - size_of::<LlmpPage>()) as u64;
        assert!(map.msg_from_offset(page_size).is_err());
        assert!(
            map.msg_from_offset(page_size - size_of::<LlmpMsg>() as u64 + 1)
                .is_err()
        );
        assert!(
            map.msg_from_offset(page_size - size_of::<LlmpMsg>() as u64)
                .is_ok()
        );
    }

    /// Regression test 13: `LlmpBroker::broker_once` accumulates `new_messages |= has_messages`,
    /// returning `Ok(true)` when client 0 sends a message and client 1 is idle.
    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_proof_broker_once_overwrites_new_messages() {
        use tuple_list::tuple_list;

        use crate::{LlmpBroker, LlmpReceiver, LlmpSender};

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut broker = LlmpBroker::new(shmem_provider.clone(), tuple_list!()).unwrap();

        let mut sender0 = LlmpSender::new(shmem_provider.clone(), ClientId(1), true).unwrap();
        let sender1 = LlmpSender::new(shmem_provider.clone(), ClientId(2), true).unwrap();

        let recv0 = LlmpReceiver::on_existing_shmem(
            shmem_provider.clone(),
            shmem_provider
                .clone_ref(&sender0.out_shmems[0].shmem)
                .unwrap(),
            None,
        )
        .unwrap();
        let recv1 = LlmpReceiver::on_existing_shmem(
            shmem_provider.clone(),
            shmem_provider
                .clone_ref(&sender1.out_shmems[0].shmem)
                .unwrap(),
            None,
        )
        .unwrap();

        broker.inner_mut().add_client(recv0);
        broker.inner_mut().add_client(recv1);

        sender0.send_buf(Tag(0x1234), &[1, 2, 3]).unwrap();

        let had_messages = broker.broker_once().unwrap();
        assert!(!broker.inner().llmp_out.last_msg_sent.is_null());
        assert!(had_messages);
    }

    /// Regression test 14: `LlmpSender::cancel_send` and `LlmpSender::reset` reset
    /// `self.has_unsent_message = false`, allowing subsequent `alloc_next` calls to succeed.
    #[test]
    fn test_proof_cancel_send_panics_on_next_alloc() {
        use shmem_providers::NopShMemProvider;

        use crate::LlmpSender;

        let shmem_provider = NopShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(shmem_provider, ClientId(0), true).unwrap();

        let msg = sender.alloc_next(32).unwrap();
        unsafe {
            sender.cancel_send(msg);
        }
        let msg2 = sender.alloc_next(32).unwrap();
        assert_eq!(msg2, msg);

        unsafe {
            sender.reset();
        }
        let msg3 = sender.alloc_next(32).unwrap();
        assert_eq!(msg3, msg);
    }

    /// Regression test 18: Miri verifies `LlmpBroker::broker_once`, `handle_new_msgs`
    /// (`LLMP_TAG_CLIENT_EXIT`, `on_new_message_all` hooks mutating tag/flags/payload),
    /// `forward_msg` (without double-padding), and `LlmpReceiver::recv_buf_with_flags`
    /// have zero Stacked Borrows / provenance UB.
    #[test]
    fn test_broker_once_hooks_and_forward_msg_miri() {
        use alloc::vec::Vec;

        use shmem_providers::NopShMemProvider;
        use tuple_list::tuple_list;

        use crate::{
            ClientId, Flags, LlmpBroker, LlmpBrokerInner, LlmpHook, LlmpMsgHookResult,
            LlmpReceiver, LlmpSender,
        };

        #[derive(Debug)]
        struct MutateHook;
        impl<SHM, SP> LlmpHook<SHM, SP> for MutateHook {
            fn on_new_message(
                &mut self,
                _broker_inner: &mut LlmpBrokerInner<SHM, SP>,
                _client_id: ClientId,
                msg_tag: &mut Tag,
                msg_flags: &mut Flags,
                msg: &mut [u8],
                _new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
            ) -> Result<LlmpMsgHookResult, libafl_core::Error> {
                if *msg_tag == Tag(0x10) {
                    *msg_tag = Tag(0x20);
                    *msg_flags = Flags(0x3);
                    msg[0] ^= 0xFF;
                }
                Ok(LlmpMsgHookResult::ForwardToClients)
            }
        }

        let shmem_provider = NopShMemProvider::new().unwrap();
        let mut broker = LlmpBroker::new(shmem_provider, tuple_list!(MutateHook)).unwrap();

        let mut sender = LlmpSender::new(shmem_provider, ClientId(1), true).unwrap();
        sender.send_buf(Tag(0x10), &[0xAA]).unwrap();
        sender.send_buf(Tag(0x11), &[0xBB, 0xCC]).unwrap();
        LlmpBrokerInner::announce_client_exit(&mut sender, 0).unwrap();

        let client_shmem = sender.out_shmems.pop().unwrap().shmem;
        let recv_client =
            LlmpReceiver::on_existing_shmem(shmem_provider, client_shmem, None).unwrap();
        broker.inner_mut().add_client(recv_client);

        let had_msgs = broker.broker_once().unwrap();
        assert!(had_msgs);
        assert!(!broker.inner().has_clients());

        let broker_out_shmem = broker.inner_mut().llmp_out.out_shmems.pop().unwrap().shmem;
        let mut out_receiver =
            LlmpReceiver::on_existing_shmem(shmem_provider, broker_out_shmem, None).unwrap();

        let (cid1, tag1, flags1, buf1) = out_receiver.recv_buf_with_flags().unwrap().unwrap();
        assert_eq!(cid1, ClientId(1));
        assert_eq!(tag1, Tag(0x20));
        assert_eq!(flags1, Flags(0x3));
        assert_eq!(buf1, &[0x55]);

        let (cid2, tag2, _flags2, buf2) = out_receiver.recv_buf_with_flags().unwrap().unwrap();
        assert_eq!(cid2, ClientId(1));
        assert_eq!(tag2, Tag(0x11));
        assert_eq!(buf2, &[0xBB, 0xCC]);
        assert!(out_receiver.recv_buf().unwrap().is_none());
    }

    /// Regression test 15: `LlmpBroker::loop_forever` exits cleanly after 1 client connects and
    /// disconnects when `exit_cleanly_after == 1`.
    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_proof_loop_forever_exit_cleanly_after_off_by_one() {
        use core::num::NonZeroUsize;

        use tuple_list::tuple_list;

        use crate::{Broker, LlmpBroker, LlmpReceiver, LlmpSender};

        let mut shmem_provider = StdShMemProvider::new().unwrap();
        let mut broker = LlmpBroker::new(shmem_provider.clone(), tuple_list!()).unwrap();
        broker.set_exit_after(NonZeroUsize::new(1).unwrap());

        let mut sender0 = LlmpSender::new(shmem_provider.clone(), ClientId(0), true).unwrap();
        let recv0 = LlmpReceiver::on_existing_shmem(
            shmem_provider.clone(),
            shmem_provider
                .clone_ref(&sender0.out_shmems[0].shmem)
                .unwrap(),
            None,
        )
        .unwrap();
        broker.inner_mut().add_client(recv0);

        sender0.send_exiting().unwrap();
        broker.loop_forever(None);
        assert!(!broker.has_clients());
    }

    /// Regression test 16: `recv_tcp_msg` returns `Err` instead of panicking when the peer
    /// disconnects after sending a truncated message body.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_proof_recv_tcp_msg_panics_on_truncated_body() {
        use std::{
            io::Write,
            net::{TcpListener, TcpStream},
        };

        use crate::recv_tcp_msg;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let mut client = TcpStream::connect(addr).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        client.write_all(&16_u32.to_be_bytes()).unwrap();
        client.write_all(&[0xAA, 0xBB]).unwrap();
        drop(client);

        assert!(recv_tcp_msg(&mut server).is_err());
    }

    /// Regression test 17: `LlmpSender::on_existing_shmem` with `last_msg_sent_offset = None` on a
    /// non-empty page places `EOP` (and subsequent messages) at `size_used` with monotonic
    /// `message_id` instead of overwriting Message 1 at offset 0.
    #[test]
    fn test_proof_on_existing_shmem_eop_overwrites_first_message() {
        use core::mem::size_of;

        use shmem_providers::NopShMemProvider;

        use crate::{LLMP_TAG_END_OF_PAGE, LlmpMsg, LlmpPage, LlmpSender};

        let mut shmem_provider = NopShMemProvider::new().unwrap();
        let shmem = shmem_provider.new_shmem(1024).unwrap();
        let map = LlmpSharedMap::new(ClientId(0), shmem);
        let mut sender = LlmpSender::on_existing_shmem(shmem_provider, map.shmem, None).unwrap();

        sender.send_buf(Tag(0x1111), &[0x42; 8]).unwrap();

        let existing_shmem = sender.out_shmems.pop().unwrap().shmem;
        let mut reattached =
            LlmpSender::on_existing_shmem(shmem_provider, existing_shmem, None).unwrap();

        unsafe {
            let eop_msg = reattached.alloc_eop().unwrap();
            let page_bytes = reattached.out_shmems[0].page().cast::<u8>();
            #[expect(clippy::cast_ptr_alignment)]
            let msg1_ptr = page_bytes.add(size_of::<LlmpPage>()).cast::<LlmpMsg>();
            assert_ne!(eop_msg.cast_const(), msg1_ptr);
            assert_eq!((*msg1_ptr).tag, Tag(0x1111));
            assert_eq!((*eop_msg).tag, LLMP_TAG_END_OF_PAGE);
            assert_eq!((*eop_msg).message_id.0, (*msg1_ptr).message_id.0 + 1);
        }
    }
}
