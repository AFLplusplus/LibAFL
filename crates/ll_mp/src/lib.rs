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
#[cfg(feature = "std")]
use core::net::SocketAddr;
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
    mem::{offset_of, size_of},
    num::NonZeroUsize,
    ops::{BitAnd, BitOr, Not},
    ptr, slice,
    sync::atomic::{AtomicU16, Ordering, fence},
    time::Duration,
};
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

const _: () =
    assert!(LLMP_CFG_ALIGNNMENT.is_power_of_two() && LLMP_CFG_ALIGNNMENT >= align_of::<LlmpMsg>());

/// Max payload length guaranteeing `next_shmem_size` never overflows `usize`.
const LLMP_MAX_ALLOC_BUF_LEN: usize = (1usize << (usize::BITS - 2))
    - LLMP_PAGE_HEADER_LEN
    - EOP_MSG_SIZE
    - size_of::<LlmpMsg>()
    - LLMP_CFG_ALIGNNMENT;

#[cfg(any(unix, all(windows, feature = "std")))]
static LLMP_SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

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

#[inline]
const unsafe fn llmp_page_messages_mut_ptr(page: *mut LlmpPage) -> *mut LlmpMsg {
    unsafe { page.byte_add(LLMP_PAGE_HEADER_LEN).cast::<LlmpMsg>() }
}

#[inline]
const unsafe fn llmp_msg_buf_mut_ptr(msg: *mut LlmpMsg) -> *mut u8 {
    unsafe { (msg as *mut u8).add(size_of::<LlmpMsg>()) }
}

#[inline]
unsafe fn write_shared_map_info(dst: *mut u8, map_size: usize, shm_str: [u8; 20]) {
    unsafe {
        dst.add(offset_of!(LlmpPayloadSharedMapInfo, map_size))
            .cast::<[u8; size_of::<usize>()]>()
            .write(map_size.to_ne_bytes());
        dst.add(offset_of!(LlmpPayloadSharedMapInfo, shm_str))
            .cast::<[u8; 20]>()
            .write(shm_str);
    }
}

const _: () = assert!(size_of::<LlmpMsg>().is_multiple_of(align_of::<usize>()));

/// Volatile-copies `len` payload bytes from `src_msg` into `dst` to avoid shared-memory aliasing UB.
#[inline]
unsafe fn copy_msg_payload_volatile(src_msg: *const LlmpMsg, dst: &mut Vec<u8>, len: usize) {
    const WORD: usize = size_of::<usize>();
    const CHUNK: usize = WORD * 4;

    dst.clear();
    if len == 0 {
        return;
    }
    dst.reserve(len);
    let dst_ptr = dst.as_mut_ptr();
    let src_words = unsafe { src_msg.cast::<usize>().byte_add(size_of::<LlmpMsg>()) };
    let mut offset = 0;
    let mut chunk = [0usize; 4];
    while offset + CHUNK <= len {
        unsafe {
            let s = src_words.byte_add(offset);
            for (i, slot) in chunk.iter_mut().enumerate() {
                *slot = ptr::read_volatile(s.add(i));
            }
            ptr::copy_nonoverlapping(chunk.as_ptr().cast::<u8>(), dst_ptr.add(offset), CHUNK);
        }
        offset += CHUNK;
    }
    while offset + WORD <= len {
        unsafe {
            let w = ptr::read_volatile(src_words.byte_add(offset));
            dst_ptr
                .add(offset)
                .cast::<[u8; WORD]>()
                .write(w.to_ne_bytes());
        }
        offset += WORD;
    }
    let src_bytes = src_words.cast::<u8>();
    while offset < len {
        unsafe {
            dst_ptr
                .add(offset)
                .write(ptr::read_volatile(src_bytes.add(offset)));
        }
        offset += 1;
    }
    unsafe {
        dst.set_len(len);
    }
}

#[inline]
fn checked_msg_page_offset<SHM: ShMem>(
    map: &LlmpSharedMap<SHM>,
    msg: *const LlmpMsg,
) -> Option<usize> {
    let offset = (msg as usize).checked_sub(unsafe { map.page() } as usize)?;
    (msg.is_aligned()
        && offset >= LLMP_PAGE_HEADER_LEN
        && offset.checked_add(size_of::<LlmpMsg>())? <= map.map_size)
        .then_some(offset)
}

#[inline]
fn llmp_msg_in_map<SHM: ShMem>(map: &LlmpSharedMap<SHM>, msg: *const LlmpMsg) -> bool {
    checked_msg_page_offset(map, msg).is_some()
}

#[inline]
const fn llmp_pad_len(msg_addr: usize, buf_len: usize) -> usize {
    const MASK: usize = LLMP_CFG_ALIGNNMENT - 1;
    let rem = ((msg_addr & MASK) + (size_of::<LlmpMsg>() & MASK) + (buf_len & MASK)) & MASK;
    buf_len + ((LLMP_CFG_ALIGNNMENT - rem) & MASK)
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

/// Bind to a tcp port on the [`LLMP_BIND_ADDR`] (local, or global)
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

/// Maximum size, in bytes, we are willing to allocate for a single incoming
/// TCP message. Guards against a peer sending a bogus/huge size prefix and
/// forcing an oversized allocation before any real data has been validated.
#[cfg(feature = "std")]
const LLMP_TCP_MAX_MSG_LEN: u32 = 128 * 1024 * 1024;

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

    if size > LLMP_TCP_MAX_MSG_LEN {
        return Err(Error::illegal_state(format!(
            "Refusing to allocate {size} bytes for an incoming TCP message (max {LLMP_TCP_MAX_MSG_LEN})"
        )));
    }

    let mut bytes = vec![0; size as usize];

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
    let min_needed = max_alloc
        .saturating_mul(2)
        .saturating_add(EOP_MSG_SIZE)
        .saturating_add(LLMP_PAGE_HEADER_LEN);
    max(min_needed, LLMP_CFG_INITIAL_MAP_SIZE - 1)
        .checked_next_power_of_two()
        .expect("next_shmem_size overflowed usize")
}

/// Initialize a new `llmp_page`. The size should be relative to
/// `llmp_page->messages`
///
/// # Safety
/// Will write to the raw SHM page header, should be safe for correct [`ShMem`] implementations
unsafe fn llmp_page_init<SHM: ShMem>(
    shmem: &mut SHM,
    sender_id: ClientId,
    allow_reinit: bool,
) -> *mut LlmpPage {
    unsafe {
        #[cfg(feature = "llmp_debug")]
        log::trace!("llmp_page_init: shmem {shmem:?}");
        let map_size = shmem.len();
        assert!(
            map_size >= LLMP_PAGE_HEADER_LEN + EOP_MSG_SIZE
                && (shmem.as_ptr() as usize).is_multiple_of(align_of::<LlmpPage>()),
            "Invalid LLMP ShMem size ({map_size}) or alignment ({:p})",
            shmem.as_ptr()
        );
        let page = shmem2page_mut(shmem);
        if !allow_reinit {
            assert!(
                ptr::read_volatile(&raw const (*page).magic) != PAGE_INITIALIZED_MAGIC,
                "Tried to initialize page {page:?} twice (for shmem {shmem:?})"
            );
        }

        ptr::write_volatile(&raw mut (*page).magic, PAGE_INITIALIZED_MAGIC);
        ptr::write_volatile(&raw mut (*page).sender_id, sender_id);
        (*page).current_msg_id.store(0, Ordering::Relaxed);
        ptr::write_volatile(&raw mut (*page).max_alloc_size, 0);
        ptr::write_volatile(&raw mut (*page).size_total, map_size - LLMP_PAGE_HEADER_LEN);
        ptr::write_volatile(&raw mut (*page).size_used, 0);
        let first_msg = llmp_page_messages_mut_ptr(page);
        ptr::write_volatile(&raw mut (*first_msg).message_id, MessageId(0));
        ptr::write_volatile(&raw mut (*first_msg).tag, LLMP_TAG_UNSET);
        (*page).receivers_left_count.store(0, Ordering::Relaxed);
        (*page).receivers_joined_count.store(0, Ordering::Release);
        page
    }
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
    let Some(last_off) = checked_msg_page_offset(map, last_msg) else {
        return Err(Error::illegal_state(
            "last_msg is misaligned or outside sharedmap bounds",
        ));
    };
    unsafe {
        let padded = ptr::read_volatile(&raw const (*last_msg).buf_len_padded);
        let next_off = usize::try_from(padded)
            .ok()
            .and_then(|p| last_off.checked_add(size_of::<LlmpMsg>())?.checked_add(p));
        let page = map.page_mut();
        if let Some(off) = next_off
            && off
                .checked_add(alloc_size)
                .is_some_and(|end| end <= map.map_size)
        {
            let next_ptr = page.byte_add(off).cast::<LlmpMsg>();
            if next_ptr.is_aligned() {
                return Ok(next_ptr);
            }
        }
        Err(Error::illegal_state(format!(
            "Inconsistent data on sharedmap, or Bug (next_off was {next_off:?}, page was {page:p})"
        )))
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
    /// `this` and its `buf_len` payload bytes must be valid, initialized, and not concurrently mutated.
    #[must_use]
    pub unsafe fn as_slice_raw<'a>(this: *const Self) -> &'a [u8] {
        unsafe {
            let ptr = (this as *const u8).add(size_of::<Self>());
            let len = usize::try_from(ptr::read_volatile(&raw const (*this).buf_len))
                .expect("LlmpMsg::buf_len exceeds usize::MAX");
            slice::from_raw_parts(ptr, len)
        }
    }

    /// Gets the buffer from a raw pointer to a message as a mutable slice, with the correct length.
    ///
    /// # Safety
    /// `this` and its `buf_len` payload bytes must be valid, initialized, and exclusively accessed.
    #[must_use]
    pub unsafe fn as_slice_mut_raw<'a>(this: *mut Self) -> &'a mut [u8] {
        unsafe {
            let ptr = (this as *mut u8).add(size_of::<Self>());
            let len = usize::try_from(ptr::read_volatile(&raw const (*this).buf_len))
                .expect("LlmpMsg::buf_len exceeds usize::MAX");
            slice::from_raw_parts_mut(ptr, len)
        }
    }

    #[inline]
    fn checked_buf_len<SHM: ShMem>(this: *const Self, map: &LlmpSharedMap<SHM>) -> Option<usize> {
        let offset = checked_msg_page_offset(map, this)?;
        let max_buf_len = (map.map_size - offset - size_of::<LlmpMsg>()) as u64;
        let (buf_len, buf_len_padded) = unsafe {
            (
                ptr::read_volatile(&raw const (*this).buf_len),
                ptr::read_volatile(&raw const (*this).buf_len_padded),
            )
        };
        (buf_len <= buf_len_padded && buf_len_padded <= max_buf_len)
            .then(|| usize::try_from(buf_len).ok())
            .flatten()
    }

    /// Gets the buffer from this message as slice, with the correct length.
    ///
    /// # Safety
    /// The message payload must be initialized and not concurrently mutated during `'a`.
    #[inline]
    pub unsafe fn try_as_slice<'a, SHM: ShMem>(
        &self,
        map: &'a LlmpSharedMap<SHM>,
    ) -> Result<&'a [u8], Error> {
        if let Some(len) = Self::checked_buf_len(ptr::from_ref(self), map) {
            let page_ptr = unsafe { map.page().cast::<u8>() };
            let buf_addr = (ptr::from_ref(self) as usize) + size_of::<Self>();
            Ok(unsafe { slice::from_raw_parts(page_ptr.with_addr(buf_addr), len) })
        } else {
            Err(Error::illegal_state(
                "Current message not in page. The sharedmap get tampered with or we have a BUG.",
            ))
        }
    }

    /// Gets the buffer from this message as mutable slice, with the correct length.
    ///
    /// # Safety
    /// The message payload must be initialized and exclusively accessed during `'a`.
    #[inline]
    pub unsafe fn try_as_slice_mut<'a, SHM: ShMem>(
        &mut self,
        map: &'a mut LlmpSharedMap<SHM>,
    ) -> Result<&'a mut [u8], Error> {
        if let Some(len) = Self::checked_buf_len(ptr::from_ref(self), map) {
            let page_ptr = unsafe { map.page_mut().cast::<u8>() };
            let buf_addr = (ptr::from_ref(self) as usize) + size_of::<Self>();
            Ok(unsafe { slice::from_raw_parts_mut(page_ptr.with_addr(buf_addr), len) })
        } else {
            Err(Error::illegal_state(
                "Current message not in page. The sharedmap get tampered with or we have a BUG.",
            ))
        }
    }

    /// Returns `true`, if the pointer is, indeed, in the page of this shared map.
    #[inline]
    pub fn in_shmem<SHM: ShMem>(&self, map: &LlmpSharedMap<SHM>) -> bool {
        Self::checked_buf_len(ptr::from_ref(self), map).is_some()
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
        count.fetch_add(1, Ordering::AcqRel);
        #[cfg(not(target_has_atomic = "16"))]
        count.store(
            count.load(Ordering::Acquire).wrapping_add(1),
            Ordering::Release,
        );
    }

    #[inline]
    unsafe fn receiver_join_if_unjoined(this: *const Self) {
        let count = unsafe { &(*this).receivers_joined_count };
        #[cfg(target_has_atomic = "16")]
        if count
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {}
        #[cfg(not(target_has_atomic = "16"))]
        if count.load(Ordering::Acquire) == 0 {
            count.store(1, Ordering::Release);
        }
    }

    #[inline]
    unsafe fn receiver_left(this: *const Self) {
        let count = unsafe { &(*this).receivers_left_count };
        #[cfg(target_has_atomic = "16")]
        count.fetch_add(1, Ordering::AcqRel);
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
        let expected_size_total = out_shmem.map_size - LLMP_PAGE_HEADER_LEN;
        let (size_used, client_id) = unsafe {
            let page = out_shmem.page();
            (
                ptr::read_volatile(&raw const (*page).size_used),
                ptr::read_volatile(&raw const (*page).sender_id),
            )
        };
        if size_used > expected_size_total || !size_used.is_multiple_of(align_of::<LlmpMsg>()) {
            return Err(Error::illegal_state(format!(
                "Corrupted LLMP sender page size_used ({size_used} / {expected_size_total})"
            )));
        }
        let last_msg_sent = match last_msg_sent_offset {
            Some(offset) => out_shmem.msg_from_offset(offset)?,
            None => ptr::null_mut(),
        };

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
            // Exclude the current page; load `left` before `joined` (both Acquire) to avoid ABA.
            let mut unmap_until_excl = 0;
            for map in self.out_shmems.split_last_mut().unwrap().1 {
                let page = map.page();
                let left = (*page).receivers_left_count.load(Ordering::Acquire);
                if left == 0 {
                    break;
                }
                let joined = (*page).receivers_joined_count.load(Ordering::Acquire);
                if joined != left {
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
                    ptr::write_volatile(&raw mut (*msg).tag, LLMP_SLOW_RECEIVER_PANIC);
                    ptr::write_volatile(&raw mut (*msg).flags, LLMP_FLAG_INITIALIZED);
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
                    ptr::read_volatile(&raw const (*page).magic) == PAGE_INITIALIZED_MAGIC,
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
            // Find a cached shared map that all receivers have left (`left` loaded before `joined`).
            let cached_shmem = self
                .unused_shmem_cache
                .iter()
                .position(|cached_shmem| {
                    let page = cached_shmem.page();
                    let left = (*page).receivers_left_count.load(Ordering::Acquire);
                    left != 0 && (*page).receivers_joined_count.load(Ordering::Acquire) == left
                })
                .map(|e| self.unused_shmem_cache.remove(e));

            match cached_shmem {
                Some(mut cached_shmem) => {
                    // We got cached shmems laying around, hand it out, if they are large enough.
                    if cached_shmem.map_size < next_min_shmem_size {
                        #[cfg(feature = "llmp_debug")]
                        log::info!("Dropping too small shmem {cached_shmem:?}");
                        drop(cached_shmem);
                        self.new_or_unused_shmem(sender_id, next_min_shmem_size)
                    } else {
                        #[cfg(feature = "llmp_debug")]
                        log::info!("Returning cached shmem {cached_shmem:?}");
                        let page = cached_shmem.page_mut();
                        ptr::write_volatile(&raw mut (*page).magic, PAGE_DEINITIALIZED_MAGIC);
                        cached_shmem.page =
                            llmp_page_init(&mut cached_shmem.shmem, sender_id, false);
                        Ok(cached_shmem)
                    }
                }
                _ => Ok(LlmpSharedMap::new(
                    sender_id,
                    self.shmem_provider.new_shmem(next_min_shmem_size)?,
                )),
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
                    shm.map_size,
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
            let old_max_alloc = ptr::read_volatile(&raw const (*old_map).max_alloc_size);
            let old_sender_id = ptr::read_volatile(&raw const (*old_map).sender_id);
            let next_min_shmem_size = next_shmem_size(old_max_alloc);

            #[cfg(feature = "llmp_debug")]
            log::info!("Next min ShMem Size {next_min_shmem_size}");

            // Get a new shared page, or reuse an old one, if available.
            let mut new_map_shmem = self.new_or_unused_shmem(old_sender_id, next_min_shmem_size)?;
            let new_map = new_map_shmem.page_mut();

            #[cfg(feature = "llmp_debug")]
            log::info!("got new map at: {new_map:?}, max alloc: {old_max_alloc:?}");

            ptr::write_volatile(&raw mut (*new_map).max_alloc_size, old_max_alloc);
            (*new_map).current_msg_id.store(0, Ordering::Release);

            /* On the old map, place a last message linking to the new map for the clients
             * to consume */
            let out = self.alloc_eop()?;

            write_shared_map_info(
                llmp_msg_buf_mut_ptr(out),
                new_map_shmem.map_size,
                *new_map_shmem.shmem.id().as_array(),
            );

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
        if buf_len > LLMP_MAX_ALLOC_BUF_LEN {
            return Err(Error::illegal_argument(format!(
                "Requested LLMP message size {buf_len} exceeds maximum {LLMP_MAX_ALLOC_BUF_LEN}"
            )));
        }
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
            assert!(
                self.has_unsent_message,
                "cancel_send called with no unsent message"
            );
            let map = self.out_shmems.last_mut().unwrap();
            assert!(
                llmp_msg_in_map(map, msg),
                "cancel_send msg {msg:p} is misaligned or out of current map"
            );
            let page = map.page_mut();
            let padded = usize::try_from(ptr::read_volatile(&raw const (*msg).buf_len_padded))
                .expect("invalid buf_len_padded in cancel_send");
            let step = padded
                .checked_add(size_of::<LlmpMsg>())
                .expect("cancel_send size overflow");
            let size_used = ptr::read_volatile(&raw const (*page).size_used);
            ptr::write_volatile(&raw mut (*msg).tag, LLMP_TAG_UNSET);
            ptr::write_volatile(
                &raw mut (*page).size_used,
                size_used
                    .checked_sub(step)
                    .expect("cancel_send size_used underflow"),
            );
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

            let map = self.out_shmems.last_mut().unwrap();
            let Some(msg_off) = checked_msg_page_offset(map, msg) else {
                return Err(Error::illegal_argument(
                    "shrink_alloced msg is misaligned or not in current map",
                ));
            };
            let size_total = map.map_size - LLMP_PAGE_HEADER_LEN;
            let old_len_padded =
                usize::try_from(ptr::read_volatile(&raw const (*msg).buf_len_padded))
                    .ok()
                    .filter(|&p| p <= size_total)
                    .ok_or_else(|| {
                        Error::illegal_state("Corrupted buf_len_padded in shrink_alloced")
                    })?;
            let old_buf_len = ptr::read_volatile(&raw const (*msg).buf_len);
            if shrinked_len > old_len_padded {
                return Err(Error::illegal_argument(format!(
                    "Cannot shrink msg of size {old_buf_len} (padded: {old_len_padded}) to {shrinked_len}"
                )));
            }
            let buf_len_padded = llmp_pad_len(msg as usize, shrinked_len);
            if buf_len_padded > old_len_padded {
                return Err(Error::illegal_argument(format!(
                    "Cannot shrink msg of size {old_buf_len} (padded: {old_len_padded}) to {shrinked_len} (padded: {buf_len_padded})"
                )));
            }
            if msg_off
                .checked_add(size_of::<LlmpMsg>() * 2)
                .and_then(|o| o.checked_add(buf_len_padded))
                .is_none_or(|end| end > map.map_size)
            {
                return Err(Error::illegal_argument(
                    "shrink_alloced trailing sentinel exceeds map bounds",
                ));
            }

            let page = map.page_mut();
            let size_used = ptr::read_volatile(&raw const (*page).size_used);
            let new_size_used = size_used
                .checked_sub(old_len_padded)
                .and_then(|s| s.checked_add(buf_len_padded))
                .filter(|&s| {
                    s.checked_add(size_of::<LlmpMsg>())
                        .is_some_and(|e| e <= size_total)
                })
                .ok_or_else(|| {
                    Error::illegal_state("Corrupted page size_used in shrink_alloced")
                })?;

            ptr::write_volatile(&raw mut (*msg).buf_len, shrinked_len as u64);
            ptr::write_volatile(&raw mut (*msg).buf_len_padded, buf_len_padded as u64);
            ptr::write_volatile(&raw mut (*page).size_used, new_size_used);
            let next_msg = msg.byte_add(size_of::<LlmpMsg>() + buf_len_padded);
            ptr::write_volatile(&raw mut (*next_msg).tag, LLMP_TAG_UNSET);

            Ok(())
        }
    }

    /// Allocates a message of the given size, tags it, and sends it off.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        self.send_buf_with_flags(tag, LLMP_FLAG_INITIALIZED, buf)
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
            ptr::write_volatile(&raw mut (*msg).tag, tag);
            ptr::write_volatile(&raw mut (*msg).flags, flags);
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
            current_out_shmem.page = llmp_page_init(&mut current_out_shmem.shmem, self.id, true);
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
            current_out_shmem.write_to_env(env_name)?;
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
            let page = self.out_shmems.last_mut().unwrap().page_mut();
            LlmpPage::receiver_joined(page);
            LlmpPage::receiver_left(page);
        }
    }

    /// Intern: Special allocation function for `EOP` messages (and nothing else!)
    /// The normal alloc will fail if there is not enough space for `buf_len_padded + EOP`
    /// So if [`Self::alloc_next`] fails, create new page if necessary, use this function,
    /// place `EOP`, commit `EOP`, reset, alloc again on the new space.
    unsafe fn alloc_eop(&mut self) -> Result<*mut LlmpMsg, Error> {
        unsafe {
            let map = self.out_shmems.last_mut().unwrap();
            let size_total = map.map_size - LLMP_PAGE_HEADER_LEN;
            let page = map.page_mut();
            let last_msg = self.last_msg_sent;
            let size_used = ptr::read_volatile(&raw const (*page).size_used);
            assert!(
                size_used.is_multiple_of(align_of::<LlmpMsg>())
                    && size_used.saturating_add(EOP_MSG_SIZE) <= size_total,
                "PROGRAM ABORT : BUG: EOP does not fit or size_used misaligned! page {page:?}, size_used {size_used}, size_total {size_total}"
            );

            let ret: *mut LlmpMsg = if last_msg.is_null() {
                page.byte_add(LLMP_PAGE_HEADER_LEN + size_used)
                    .cast::<LlmpMsg>()
            } else {
                llmp_next_msg_ptr_checked(map, last_msg, EOP_MSG_SIZE)?
            };
            assert!(
                !self.has_unsent_message
                    && ptr::read_volatile(&raw const (*ret).tag) != LLMP_TAG_UNINITIALIZED,
                "Did not call send() on last message!"
            );

            let eop_len = size_of::<LlmpPayloadSharedMapInfo>() as u64;
            ptr::write_volatile(&raw mut (*ret).buf_len, eop_len);

            // We don't need to pad the EOP message: it'll always be the last in this page.
            ptr::write_volatile(&raw mut (*ret).buf_len_padded, eop_len);
            let next_id = if last_msg.is_null() {
                MessageId((*page).current_msg_id.load(Ordering::Relaxed) + 1)
            } else {
                MessageId(ptr::read_volatile(&raw const (*last_msg).message_id).0 + 1)
            };
            ptr::write_volatile(&raw mut (*ret).broker, BrokerId(0));
            ptr::write_volatile(&raw mut (*ret).flags, LLMP_FLAG_INITIALIZED);
            ptr::write_volatile(&raw mut (*ret).message_id, next_id);
            ptr::write_volatile(&raw mut (*ret).tag, LLMP_TAG_END_OF_PAGE);
            ptr::write_volatile(&raw mut (*page).size_used, size_used + EOP_MSG_SIZE);
            Ok(ret)
        }
    }

    /// Intern: Will return a ptr to the next msg buf, or None if map is full.
    /// Never call [`Self::alloc_next`] without either sending or cancelling the last allocated message for this page!
    /// There can only ever be up to one message allocated per page at each given time.
    unsafe fn alloc_next_if_space(&mut self, buf_len: usize) -> Option<*mut LlmpMsg> {
        if buf_len > LLMP_MAX_ALLOC_BUF_LEN {
            return None;
        }
        unsafe {
            let map = self.out_shmems.last_mut().unwrap();
            let size_total = map.map_size - LLMP_PAGE_HEADER_LEN;
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

            let size_used = ptr::read_volatile(&raw const (*page).size_used);
            assert!(
                size_used <= size_total && size_used.is_multiple_of(align_of::<LlmpMsg>()),
                "Corrupted LLMP page size_used ({size_used} / {size_total}) on page {page:p}"
            );

            let msg_addr = (page as usize) + LLMP_PAGE_HEADER_LEN + size_used;
            let buf_len_padded = llmp_pad_len(msg_addr, buf_len);
            let alloc_padded = size_of::<LlmpMsg>() + buf_len_padded;

            #[cfg(feature = "llmp_debug")]
            log::trace!(
                "{page:p} size_used={size_used:x} buf_len_padded={buf_len_padded:x} EOP_MSG_SIZE={EOP_MSG_SIZE:x} size_total={size_total}"
            );

            let prev_max = ptr::read_volatile(&raw const (*page).max_alloc_size);
            if alloc_padded > prev_max {
                ptr::write_volatile(&raw mut (*page).max_alloc_size, alloc_padded);
            }

            if alloc_padded + EOP_MSG_SIZE > size_total - size_used {
                #[cfg(feature = "llmp_debug")]
                log::info!("LLMP: Page full.");
                return None;
            }

            let ret = page
                .byte_add(LLMP_PAGE_HEADER_LEN + size_used)
                .cast::<LlmpMsg>();

            /* We need to start with 1 for ids, as current message id is initialized
             * with 0... */
            let next_msg_id = if last_msg.is_null() {
                MessageId((*page).current_msg_id.load(Ordering::Relaxed) + 1)
            } else {
                let last_id = ptr::read_volatile(&raw const (*last_msg).message_id);
                if (*page).current_msg_id.load(Ordering::Relaxed) == last_id.0 {
                    MessageId(last_id.0 + 1)
                } else {
                    /* Oops, wrong usage! */
                    panic!(
                        "BUG: The current message never got committed using send! (page->current_msg_id {:?}, last_msg->message_id: {last_id:?})",
                        &raw const (*page).current_msg_id,
                    );
                }
            };
            ptr::write_volatile(&raw mut (*ret).broker, BrokerId(0));
            ptr::write_volatile(&raw mut (*ret).flags, LLMP_FLAG_INITIALIZED);
            ptr::write_volatile(&raw mut (*ret).message_id, next_msg_id);
            ptr::write_volatile(&raw mut (*ret).buf_len, buf_len as u64);
            ptr::write_volatile(&raw mut (*ret).buf_len_padded, buf_len_padded as u64);
            ptr::write_volatile(&raw mut (*page).size_used, size_used + alloc_padded);

            let next_sentinel = ret.byte_add(alloc_padded);
            ptr::write_volatile(&raw mut (*next_sentinel).tag, LLMP_TAG_UNSET);
            ptr::write_volatile(&raw mut (*ret).tag, LLMP_TAG_UNINITIALIZED);

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
            assert!(
                !ptr::addr_eq(self.last_msg_sent, msg),
                "Message sent twice!"
            );
            let map = self.out_shmems.last_mut().unwrap();
            if msg.is_null() || !llmp_msg_in_map(map, msg) {
                return Err(Error::unknown(format!(
                    "Llmp Message {msg:?} is null or not in current page"
                )));
            }
            assert!(
                ptr::read_volatile(&raw const (*msg).tag) != LLMP_TAG_UNSET,
                "No tag set on message with id {:?}",
                ptr::read_volatile(&raw const (*msg).message_id)
            );
            // A client gets the sender id assigned to by the broker during the initial handshake.
            if overwrite_client_id {
                ptr::write_volatile(&raw mut (*msg).sender, self.id);
            }
            let page = map.page_mut();

            let mid = (*page).current_msg_id.load(Ordering::Relaxed) + 1;
            ptr::write_volatile(&raw mut (*msg).message_id, MessageId(mid));

            // Make sure all things have been written to the page, and commit the message to the page
            (*page).current_msg_id.store(mid, Ordering::Release);

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
            shmem: map.description(),
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
    /// Receiver-owned buffer holding volatile-copied payload bytes for safe `recv_buf*` slices
    recv_scratch: Vec<u8>,
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
        Self::on_existing_shmem_inner(
            shmem_provider.clone(),
            shmem_provider.existing_from_env(env_name)?,
            msg_offset_from_env(env_name)?,
            false,
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
        let join_new = last_msg_recvd_offset.is_none();
        Self::on_existing_shmem_inner(
            shmem_provider,
            current_sender_shmem,
            last_msg_recvd_offset,
            join_new,
        )
    }

    fn on_existing_shmem_inner(
        shmem_provider: SP,
        current_sender_shmem: SHM,
        last_msg_recvd_offset: Option<u64>,
        join_new: bool,
    ) -> Result<Self, Error> {
        let mut current_recv_shmem = LlmpSharedMap::existing(current_sender_shmem);
        let last_msg_recvd = match last_msg_recvd_offset {
            Some(offset) => current_recv_shmem.msg_from_offset(offset)?,
            None => ptr::null_mut(),
        };
        unsafe {
            if join_new {
                LlmpPage::receiver_joined(current_recv_shmem.page_mut());
            } else {
                LlmpPage::receiver_join_if_unjoined(current_recv_shmem.page_mut());
            }
        }

        Ok(Self {
            id: ClientId(0),
            current_recv_shmem,
            last_msg_recvd,
            shmem_provider,
            highest_msg_id: MessageId(0),
            recv_scratch: Vec::new(),
            #[cfg(feature = "std")]
            last_msg_time: current_time(),
        })
    }

    /// Read next message with its single-fetched [`Tag`] and validated length (without updating `last_msg_time`).
    #[inline(never)]
    unsafe fn recv_checked(&mut self) -> Result<Option<(*mut LlmpMsg, Tag, usize)>, Error> {
        unsafe {
            loop {
                let page = self.current_recv_shmem.page_mut();
                let last_msg = self.last_msg_recvd;
                let last_id = if last_msg.is_null() {
                    MessageId(0)
                } else {
                    ptr::read_volatile(&raw const (*last_msg).message_id)
                };

                if self.highest_msg_id <= last_id {
                    let cur = MessageId((*page).current_msg_id.load(Ordering::Relaxed));
                    if cur <= last_id {
                        return Ok(None);
                    }
                    fence(Ordering::Acquire);
                    self.highest_msg_id = cur;
                }

                let msg = if last_msg.is_null() {
                    llmp_page_messages_mut_ptr(page)
                } else {
                    llmp_next_msg_ptr_checked(
                        &mut self.current_recv_shmem,
                        last_msg,
                        size_of::<LlmpMsg>(),
                    )?
                };

                let Some(checked_len) = LlmpMsg::checked_buf_len(msg, &self.current_recv_shmem)
                else {
                    return Err(Error::illegal_state(
                        "Unexpected message in map (out of map bounds) - buggy client or tampered shared map detected!",
                    ));
                };

                log::debug!(
                    "[{} - {:#x}] Received message with ID {}...",
                    self.id.0,
                    ptr::from_ref::<Self>(self) as u64,
                    ptr::read_volatile(&raw const (*msg).message_id).0
                );

                // Handle special, LLMP internal, messages using single-fetched `checked_len`.
                let tag = ptr::read_volatile(&raw const (*msg).tag);
                match tag {
                    LLMP_TAG_UNSET => {
                        panic!("BUG: Read unallocated msg (tag was {LLMP_TAG_UNSET:?})")
                    }
                    LLMP_TAG_EXITING => {
                        // The other side is done.
                        if checked_len != 0 {
                            return Err(Error::illegal_state(format!(
                                "Non-empty LLMP_TAG_EXITING message (len {checked_len})"
                            )));
                        }
                        return Err(Error::shutting_down());
                    }
                    LLMP_TAG_END_OF_PAGE => {
                        log::debug!("Received end of page, allocating next");
                        if checked_len < size_of::<LlmpPayloadSharedMapInfo>() {
                            return Err(Error::illegal_state(format!(
                                "Illegal message length for EOP (got {checked_len}, expected at least {})",
                                size_of::<LlmpPayloadSharedMapInfo>()
                            )));
                        }

                        let pageinfo_cpy = llmp_msg_buf_mut_ptr(msg)
                            .cast::<LlmpPayloadSharedMapInfo>()
                            .read_unaligned();

                        // Join the next page before leaving the old page (hand-over-hand refcount).
                        let mut next_recv_shmem =
                            LlmpSharedMap::existing(self.shmem_provider.shmem_from_id_and_size(
                                ShMemId::from_array(&pageinfo_cpy.shm_str),
                                pageinfo_cpy.map_size,
                            )?);
                        LlmpPage::receiver_joined(next_recv_shmem.page_mut());
                        LlmpPage::receiver_left(page);

                        self.last_msg_recvd = ptr::null();
                        self.highest_msg_id = MessageId(0);
                        self.current_recv_shmem = next_recv_shmem;

                        #[cfg(feature = "llmp_debug")]
                        log::info!(
                            "LLMP_DEBUG: Got a new recv map {} with len {:?}",
                            self.current_recv_shmem.shmem.id(),
                            self.current_recv_shmem.map_size
                        );
                    }
                    _ => {
                        self.last_msg_recvd = msg;
                        return Ok(Some((msg, tag, checked_len)));
                    }
                }
            }
        }
    }

    /// Read next message.
    /// Returns a pointer to the [`LlmpMsg`], `None` of no message exists, or an [`Error`].
    ///
    /// Will *not* update `self.last_msg_time`.
    #[inline]
    unsafe fn recv(&mut self) -> Result<Option<*mut LlmpMsg>, Error> {
        unsafe { Ok(self.recv_checked()?.map(|(msg, _, _)| msg)) }
    }

    unsafe fn recv_blocking_checked(&mut self) -> Result<(*mut LlmpMsg, Tag, usize), Error> {
        loop {
            if let Some(res) = unsafe { self.recv_checked()? } {
                return Ok(res);
            }
            hint::spin_loop();
        }
    }

    /// Blocks/spins until the next message gets posted to the page,
    /// then returns that message.
    /// # Safety
    /// Returns a raw ptr, on the recv map. Should be safe in general
    pub unsafe fn recv_blocking(&mut self) -> Result<*mut LlmpMsg, Error> {
        unsafe { Ok(self.recv_blocking_checked()?.0) }
    }

    #[inline]
    unsafe fn copy_msg_to_scratch(
        &mut self,
        msg: *mut LlmpMsg,
        tag: Tag,
        checked_len: usize,
    ) -> (ClientId, Tag, Flags, &[u8]) {
        unsafe {
            let sender = ptr::read_volatile(&raw const (*msg).sender);
            let flags = ptr::read_volatile(&raw const (*msg).flags);
            copy_msg_payload_volatile(msg, &mut self.recv_scratch, checked_len);
            (sender, tag, flags, &self.recv_scratch)
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
        unsafe {
            match self.recv_checked()? {
                Some((msg, tag, checked_len)) => {
                    Ok(Some(self.copy_msg_to_scratch(msg, tag, checked_len)))
                }
                None => Ok(None),
            }
        }
    }

    /// Receive the buffer, also reading the LLMP internal message flags
    #[inline]
    pub fn recv_buf_blocking_with_flags(&mut self) -> Result<(ClientId, Tag, Flags, &[u8]), Error> {
        unsafe {
            let (msg, tag, checked_len) = self.recv_blocking_checked()?;
            Ok(self.copy_msg_to_scratch(msg, tag, checked_len))
        }
    }

    /// Returns the next sender, tag, buf, looping until it becomes available
    #[inline]
    pub fn recv_buf_blocking(&mut self) -> Result<(ClientId, Tag, &[u8]), Error> {
        let (sender, tag, _flags, buf) = self.recv_buf_blocking_with_flags()?;
        Ok((sender, tag, buf))
    }

    /// Create this client on an existing map from the given description. acquired with `self.describe`
    pub fn on_existing_from_description(
        mut shmem_provider: SP,
        description: &LlmpDescription,
    ) -> Result<Self, Error> {
        Self::on_existing_shmem_inner(
            shmem_provider.clone(),
            shmem_provider.shmem_from_description(description.shmem)?,
            description.last_message_offset,
            false,
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
            current_out_shmem.write_to_env(env_name)?;
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
            shmem: map.description(),
            last_message_offset,
        })
    }
}

/// A page wrapper
pub struct LlmpSharedMap<SHM> {
    /// Shmem containg the actual (unsafe) page,
    /// shared between one `LlmpSender` and one `LlmpReceiver`
    shmem: SHM,
    page: *mut LlmpPage,
    map_size: usize,
}

impl<SHM> Debug for LlmpSharedMap<SHM> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LlmpSharedMap")
            .field("page", &self.page)
            .field("map_size", &self.map_size)
            .finish_non_exhaustive()
    }
}

// SAFETY: `self.page` aliases the address-stable mapping owned by `self.shmem`, and raw accesses remain `unsafe`.
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
        let page = unsafe { llmp_page_init(&mut new_shmem, sender, false) };
        Self {
            shmem: new_shmem,
            page,
            map_size,
        }
    }

    /// Maps and wraps an existing
    pub fn existing(mut existing_shmem: SHM) -> Self {
        #[cfg(feature = "llmp_debug")]
        log::info!(
            "LLMP_DEBUG: Using existing map {} with size {}",
            existing_shmem.id(),
            existing_shmem.len(),
        );

        let map_size = existing_shmem.len();
        assert!(
            map_size >= LLMP_PAGE_HEADER_LEN + EOP_MSG_SIZE
                && (existing_shmem.as_ptr() as usize).is_multiple_of(align_of::<LlmpPage>()),
            "Invalid existing LLMP ShMem size ({map_size}) or alignment ({:p})",
            existing_shmem.as_ptr()
        );
        let page = unsafe { shmem2page_mut(&mut existing_shmem) };
        let ret = Self {
            shmem: existing_shmem,
            page,
            map_size,
        };
        unsafe {
            let page = ret.page();
            assert!(
                ptr::read_volatile(&raw const (*page).magic) == PAGE_INITIALIZED_MAGIC,
                "Map was not priviously initialized at {ret:?}"
            );
            let expected_size_total = map_size - LLMP_PAGE_HEADER_LEN;
            let size_total = ptr::read_volatile(&raw const (*page).size_total);
            assert!(
                size_total == expected_size_total,
                "Corrupted LLMP page size_total at {ret:?} (size_total={size_total}, expected={expected_size_total})"
            );
        }
        ret
    }

    /// Returns this map's [`ShMemDescription`].
    #[inline]
    #[must_use]
    pub fn description(&self) -> ShMemDescription {
        ShMemDescription {
            size: self.map_size,
            id: self.shmem.id(),
        }
    }

    /// Writes this map's id and size to env.
    ///
    /// # Safety
    /// Writes to env variables and may only be done single-threaded.
    #[cfg(feature = "std")]
    pub unsafe fn write_to_env(&self, env_name: &str) -> Result<(), Error> {
        unsafe {
            env::set_var(env_name, self.shmem.id().to_string());
            env::set_var(format!("{env_name}_SIZE"), format!("{}", self.map_size));
        }
        Ok(())
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
    pub unsafe fn msg_to_offset(&self, msg: *const LlmpMsg) -> Result<u64, Error> {
        if let Some(page_offset) = checked_msg_page_offset(self, msg) {
            Ok((page_offset - LLMP_PAGE_HEADER_LEN) as u64)
        } else {
            let page = unsafe { self.page() };
            Err(Error::illegal_argument(format!(
                "Message ({msg:p}) not in page ({page:p})"
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
    /// Will return [`crate::Error::illegal_argument`] error if the offset is out of bounds or unaligned.
    pub fn msg_from_offset(&mut self, offset: u64) -> Result<*mut LlmpMsg, Error> {
        let page = unsafe { self.page_mut() };
        let page_size = self.map_size.saturating_sub(size_of::<LlmpPage>());
        let Some(offset) = usize::try_from(offset).ok().filter(|offset| {
            offset.is_multiple_of(align_of::<LlmpMsg>())
                && offset
                    .checked_add(size_of::<LlmpMsg>())
                    .is_some_and(|end| end <= page_size)
        }) else {
            return Err(Error::illegal_argument(format!(
                "Msg offset out of bounds or unaligned (size: {page_size}, requested offset: {offset})"
            )));
        };
        unsafe { Ok(llmp_page_messages_mut_ptr(page).byte_add(offset)) }
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
    /// Reusable staging buffer for volatile message payload copies before invoking hooks
    staging_buf: Vec<u8>,
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
/// On unix, it handles signals; on Windows, control signals (e.g., CTRL+C).
#[cfg(any(unix, all(windows, feature = "std")))]
#[derive(Debug, Copy, Clone, Default)]
pub struct LlmpShutdownSignalHandler;

#[cfg(all(unix, feature = "alloc"))]
impl SignalHandler for LlmpShutdownSignalHandler {
    unsafe fn handle(
        &mut self,
        _signal: Signal,
        _info: &mut siginfo_t,
        _context: Option<&mut ucontext_t>,
    ) {
        LLMP_SHUTTING_DOWN.store(true, Ordering::Relaxed);
    }

    fn signals(&self) -> Vec<Signal> {
        vec![Signal::SigTerm, Signal::SigInterrupt, Signal::SigQuit]
    }
}

#[cfg(all(windows, feature = "std"))]
impl CtrlHandler for LlmpShutdownSignalHandler {
    fn handle(&mut self, ctrl_type: u32) -> bool {
        log::info!("LLMP: Received shutdown signal, ctrl_type {ctrl_type:?}");
        LLMP_SHUTTING_DOWN.store(true, Ordering::Relaxed);
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
            staging_buf: self.staging_buf,
        }
    }
}

#[cfg(any(all(unix, feature = "alloc", not(miri)), all(windows, feature = "std")))]
fn setup_shutdown_handlers() {
    let handler_ptr = ptr::NonNull::<LlmpShutdownSignalHandler>::dangling().as_ptr();
    #[cfg(all(unix, not(miri)))]
    if let Err(e) = unsafe { setup_signal_handler(handler_ptr) } {
        // We can live without a proper ctrl+c signal handler - Ignore.
        log::info!("Failed to setup signal handlers: {e}");
    } else {
        log::info!("Successfully setup signal handlers");
    }

    #[cfg(all(windows, feature = "std"))]
    if let Err(e) = unsafe { setup_ctrl_handler(handler_ptr) } {
        // We can live without a proper ctrl+c signal handler - Ignore.
        log::info!("Failed to setup control handlers: {e}");
    } else {
        log::info!(
            "{}: Broker successfully setup control handlers",
            std::process::id()
        );
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

    /// Loops until the last client quits the last broker,
    /// forwarding and handling all incoming messages from clients for each broker.
    /// Will call `on_timeout` roughly after `timeout`
    /// Panics on error.
    /// 5 millis of sleep can't hurt to keep busywait not at 100%
    #[cfg(feature = "std")]
    pub fn loop_with_timeouts(&mut self, timeout: Duration, sleep_time: Option<Duration>) {
        use no_std_time::current_milliseconds;

        #[cfg(any(all(unix, feature = "alloc", not(miri)), all(windows, feature = "std")))]
        setup_shutdown_handlers();

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
            staging_buf: Vec::new(),
        })
    }

    /// Create a new [`LlmpBroker`] attaching to a TCP port
    #[cfg(feature = "std")]
    pub fn create_attach_to_tcp(shmem_provider: SP, hooks: HT, port: u16) -> Result<Self, Error> {
        log::info!("LlmpBroker: creating on port {port}");
        let inner = LlmpBrokerInner::create_attach_to_tcp(shmem_provider, port)?;
        log::info!("LlmpBroker: created inner on port {port}");
        Ok(LlmpBroker {
            inner,
            hooks,
            staging_buf: Vec::new(),
        })
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
            staging_buf: Vec::new(),
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
        setup_shutdown_handlers();

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
        setup_shutdown_handlers();

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
        let mut i = 0;
        while i < self.inner.llmp_clients.len() {
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
            i += 1;
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
    #[expect(clippy::too_many_lines)]
    unsafe fn handle_new_msgs(&mut self, client_id: ClientId) -> Result<bool, Error> {
        unsafe {
            let mut new_messages = false;

            // TODO: We could memcpy a range of pending messages, instead of one by one.
            loop {
                // log::trace!("{:#?}", self.llmp_clients);
                let (msg, tag, checked_len) = {
                    let pos = if (client_id.0 as usize) < self.inner.llmp_clients.len()
                        && self.inner.llmp_clients[client_id.0 as usize].id == client_id
                    {
                        // Fast path when no client before this one was removed
                        client_id.0 as usize
                    } else if let Ok(pos) = self
                        .inner
                        .llmp_clients
                        .binary_search_by_key(&client_id, |x| x.id)
                    {
                        pos
                    } else {
                        // Client was removed or `self.inner` was replaced by an earlier hook.
                        return Ok(new_messages);
                    };
                    let client = &mut self.inner.llmp_clients[pos];
                    let Some((msg, tag, checked_len)) = client.recv_checked()? else {
                        // We're done handling this client
                        #[cfg(feature = "std")]
                        if new_messages {
                            // set the recv time
                            // We don't do that in recv() to keep calls to `current_time` to a minimum.
                            client.last_msg_time = current_time();
                        }
                        return Ok(new_messages);
                    };
                    (msg, tag, checked_len)
                };
                new_messages = true;

                match tag {
                    // first, handle the special, llmp-internal messages
                    LLMP_SLOW_RECEIVER_PANIC => {
                        return Err(Error::unknown(format!(
                            "The broker was too slow to handle messages of client {client_id:?} in time, so it quit. Either the client sent messages too fast, or we (the broker) got stuck!"
                        )));
                    }
                    LLMP_TAG_CLIENT_EXIT => {
                        if checked_len < size_of::<LlmpClientExitInfo>() {
                            log::info!(
                                "Ignoring broken CLIENT_EXIT msg due to incorrect size. Expected {} but got {checked_len}",
                                size_of::<LlmpClientExitInfo>(),
                            );
                            #[cfg(not(feature = "std"))]
                            return Err(Error::unknown(format!(
                                "Broken CLIENT_EXIT msg with incorrect size received. Expected {} but got {checked_len}",
                                size_of::<LlmpClientExitInfo>(),
                            )));
                            #[cfg(feature = "std")]
                            continue;
                        }
                        let exitinfo = llmp_msg_buf_mut_ptr(msg)
                            .cast::<LlmpClientExitInfo>()
                            .read_unaligned();
                        let client_id = ClientId(exitinfo.client_id);
                        log::info!(
                            "Client exit message received!, we are removing clients whose client_group_id is {client_id:#?}"
                        );

                        self.inner.clients_to_remove.push(client_id);
                    }
                    LLMP_TAG_NEW_SHM_CLIENT => {
                        /* This client informs us about yet another new client
                        add it to the list! Also, no need to forward this msg. */
                        if checked_len < size_of::<LlmpPayloadSharedMapInfo>() {
                            log::info!(
                                "Ignoring broken CLIENT_ADDED msg due to incorrect size. Expected {} but got {checked_len}",
                                size_of::<LlmpPayloadSharedMapInfo>(),
                            );
                            #[cfg(not(feature = "std"))]
                            return Err(Error::unknown(format!(
                                "Broken CLIENT_ADDED msg with incorrect size received. Expected {} but got {checked_len}",
                                size_of::<LlmpPayloadSharedMapInfo>(),
                            )));
                            #[cfg(feature = "std")]
                            continue;
                        }
                        let pageinfo = llmp_msg_buf_mut_ptr(msg)
                            .cast::<LlmpPayloadSharedMapInfo>()
                            .read_unaligned();
                        match self.inner.shmem_provider.shmem_from_id_and_size(
                            ShMemId::from_array(&pageinfo.shm_str),
                            pageinfo.map_size,
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
                                    recv_scratch: Vec::new(),
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
                        let orig_sender = ptr::read_volatile(&raw const (*msg).sender);
                        let orig_broker = ptr::read_volatile(&raw const (*msg).broker);
                        let mut local_tag = tag;
                        let mut local_flags = ptr::read_volatile(&raw const (*msg).flags);
                        copy_msg_payload_volatile(msg, &mut self.staging_buf, checked_len);

                        let mut new_msgs: Vec<(Tag, Flags, Vec<u8>)> = Vec::new();
                        if let LlmpMsgHookResult::ForwardToClients = self.hooks.on_new_message_all(
                            &mut self.inner,
                            client_id,
                            &mut local_tag,
                            &mut local_flags,
                            &mut self.staging_buf,
                            &mut new_msgs,
                        )? {
                            self.inner.forward_msg(
                                orig_sender,
                                orig_broker,
                                local_tag,
                                local_flags,
                                &self.staging_buf,
                            )?;
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
            recv_scratch: Vec::new(),
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
            &self.llmp_out.out_shmems.first().unwrap().description(),
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

    /// For internal use: Forward a validated, broker-staged message to the broadcast out map.
    fn forward_msg(
        &mut self,
        sender: ClientId,
        broker: BrokerId,
        tag: Tag,
        flags: Flags,
        payload: &[u8],
    ) -> Result<(), Error> {
        unsafe {
            let out: *mut LlmpMsg = self.alloc_next(payload.len())?;
            ptr::write_volatile(&raw mut (*out).sender, sender);
            ptr::write_volatile(&raw mut (*out).broker, broker);
            ptr::write_volatile(&raw mut (*out).tag, tag);
            ptr::write_volatile(&raw mut (*out).flags, flags);
            payload
                .as_ptr()
                .copy_to_nonoverlapping(llmp_msg_buf_mut_ptr(out), payload.len());
            if let Err(e) = self.llmp_out.send(out, false) {
                panic!("Error sending msg: {e:?}");
            }
            Ok(())
        }
    }

    /// Internal function, returns true when shuttdown is requested by a `SIGINT` signal
    #[inline]
    #[cfg(any(unix, all(windows, feature = "std")))]
    #[expect(clippy::unused_self)]
    fn is_shutting_down(&self) -> bool {
        LLMP_SHUTTING_DOWN.load(Ordering::Relaxed)
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
            ptr::write_volatile(&raw mut (*msg).tag, LLMP_TAG_NEW_SHM_CLIENT);
            write_shared_map_info(
                llmp_msg_buf_mut_ptr(msg),
                shmem_description.size,
                *shmem_description.id.as_array(),
            );
            sender.send(msg, true)
        }
    }

    /// Tell the broker to disconnect this client from it.
    #[cfg(feature = "std")]
    fn announce_client_exit(sender: &mut LlmpSender<SHM, SP>, client_id: u32) -> Result<(), Error> {
        unsafe {
            let msg = sender
                .alloc_next(size_of::<LlmpClientExitInfo>())
                .expect("Could not allocate a new message in shared map.");
            ptr::write_volatile(&raw mut (*msg).tag, LLMP_TAG_CLIENT_EXIT);
            llmp_msg_buf_mut_ptr(msg)
                .add(offset_of!(LlmpClientExitInfo, client_id))
                .cast::<u32>()
                .write_unaligned(client_id);
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
            let mut shmem_provider_bg = SP::new().unwrap();

            #[cfg(feature = "llmp_debug")]
            log::info!("B2b: Spawned proxy thread");

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

            let broker_shmem = shmem_provider_bg
                .shmem_from_description(broker_shmem_description)
                .expect("Failed to map local page in broker 2 broker thread!");
            let mut local_receiver =
                LlmpReceiver::on_existing_shmem(shmem_provider_bg, broker_shmem, None)
                    .expect("Failed to attach local page in broker 2 broker thread!");

            send.send(new_sender.out_shmems.first().unwrap().description())
                .expect("B2B: Error sending map description to channel!");

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

        let broker_shmem_description = self.llmp_out.out_shmems.first().unwrap().description();
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
        let tcp_out_shmem_description = tcp_out_shmem.description();
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
        mut initial_broker_shmem: LlmpSharedMap<SHM>,
        sender_id: ClientId,
    ) -> Result<Self, Error> {
        let out_shmem = LlmpSharedMap::new(
            sender_id,
            shmem_provider.new_shmem(LLMP_CFG_INITIAL_MAP_SIZE)?,
        );
        initial_broker_shmem.mark_safe_to_unmap();
        Ok(Self {
            sender: LlmpSender {
                id: sender_id,
                last_msg_sent: ptr::null_mut(),
                out_shmems: vec![out_shmem],
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
                recv_scratch: Vec::new(),
                // We don't know the last received time, just assume the current time.
                #[cfg(feature = "std")]
                last_msg_time: current_time(),
            },
        })
    }

    /// Create a point-to-point channel instead of using a broker-client channel
    pub fn new_p2p(mut shmem_provider: SP, sender_id: ClientId) -> Result<Self, Error> {
        let sender = LlmpSender::new(shmem_provider.clone(), sender_id, false)?;
        let shmem = shmem_provider.shmem_from_description(sender.out_shmems[0].description())?;
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
            receiver: LlmpReceiver::on_existing_shmem_inner(
                shmem_provider.clone(),
                current_broker_shmem,
                last_msg_recvd_offset,
                false,
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
        let client_id = unsafe { ptr::read_volatile(&raw const (*map.page()).sender_id) };
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
            shmem_description: ret.sender.out_shmems.first().unwrap().description(),
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
            ptr::write_volatile(
                &raw mut (*ret.sender.out_shmems.first_mut().unwrap().page_mut()).sender_id,
                client_sender_id,
            );
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
    #[cfg_attr(miri, ignore)]
    fn test_recv_tcp_msg_truncated_does_not_panic() {
        use std::{
            io::Write,
            net::{TcpListener, TcpStream},
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();

            let result = super::recv_tcp_msg(&mut stream);

            assert!(
                result.is_err(),
                "expected an Err, not a panic, on a truncated message"
            );
        });

        let mut client = TcpStream::connect(addr).unwrap();

        // Claim a 100-byte body...
        client.write_all(&100u32.to_be_bytes()).unwrap();

        // ...but disconnect before sending it.
        drop(client);

        handle
            .join()
            .expect("recv_tcp_msg must not panic on a truncated message");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_recv_tcp_msg_rejects_oversized_len() {
        use std::{
            io::Write,
            net::{TcpListener, TcpStream},
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let result = super::recv_tcp_msg(&mut stream);
            assert!(
                result.is_err(),
                "a bogus u32::MAX length prefix must be rejected before allocating"
            );
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client.write_all(&u32::MAX.to_be_bytes()).unwrap();
        // No body sent at all - the size cap should reject before trying to read it.

        handle.join().unwrap();
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
            let slice = unsafe { crate::LlmpMsg::as_slice_raw(msg) };
            assert_eq!(slice[0], i);
            assert_eq!(unsafe { (*msg).tag }, msg_tag);
        }
    }

    #[test]
    fn test_llmp_bounds_alignment_and_provenance() {
        use alloc::vec::Vec;
        use core::mem::size_of;

        use shmem_providers::NopShMemProvider;

        use crate::{
            LLMP_PAGE_HEADER_LEN, LlmpMsg, LlmpSender, LlmpShutdownSignalHandler,
            copy_msg_payload_volatile, llmp_msg_buf_mut_ptr, llmp_msg_in_map,
            llmp_next_msg_ptr_checked, llmp_page_messages_mut_ptr,
        };

        assert_eq!(size_of::<LlmpShutdownSignalHandler>(), 0);

        let mut sp = NopShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(sp, ClientId(1), false).unwrap();
        assert!(!sender.safe_to_unmap());
        sender.send_buf(Tag(0x1337), &[1, 2, 3, 4]).unwrap();
        let last = sender.last_msg_sent;
        let off = unsafe { sender.out_shmems[0].msg_to_offset(last).unwrap() };
        let rt = sender.out_shmems[0].msg_from_offset(off).unwrap();
        assert_eq!(rt.cast_const(), last);
        assert_eq!(
            unsafe { (*rt).try_as_slice(&sender.out_shmems[0]).unwrap() },
            &[1, 2, 3, 4]
        );
        assert!(sender.alloc_next(usize::MAX / 2).is_err());

        for _ in 0..6 {
            unsafe { sender.mark_safe_to_unmap() };
            assert!(sender.safe_to_unmap());
            for _ in 0..8 {
                sender.send_buf(Tag(0x707), &[0xAA; 512]).unwrap();
            }
        }

        let map_size = 1024;
        let mut map = LlmpSharedMap::new(ClientId(0), sp.new_shmem(map_size).unwrap());
        let page_size = (map_size - LLMP_PAGE_HEADER_LEN) as u64;
        assert!(map.msg_from_offset(1).is_err());
        assert!(map.msg_from_offset(page_size).is_err());
        assert!(
            map.msg_from_offset(page_size - size_of::<LlmpMsg>() as u64 + 1)
                .is_err()
        );
        assert!(
            map.msg_from_offset(page_size - size_of::<LlmpMsg>() as u64)
                .is_ok()
        );

        let pattern: Vec<u8> = (0u8..=160).collect();
        let mut dst = Vec::new();
        unsafe {
            let page = map.page_mut();
            assert!(!llmp_msg_in_map(&map, page.byte_add(16).cast::<LlmpMsg>()));
            let tail = page
                .byte_add(map_size - size_of::<LlmpMsg>() - 8)
                .cast::<LlmpMsg>();
            (*tail).buf_len = 8;
            (*tail).buf_len_padded = 8;
            assert!((*tail).in_shmem(&map));

            let first = llmp_page_messages_mut_ptr(map.page_mut());
            (*first).buf_len = 16;
            (*first).buf_len_padded = 16;
            LlmpMsg::as_slice_mut_raw(first)[0] = 42;
            assert_eq!(LlmpMsg::as_slice_raw(first)[0], 42);
            assert!(llmp_next_msg_ptr_checked(&mut map, first, map_size + 1).is_err());
            (*first).buf_len_padded = u64::MAX;
            assert!(llmp_next_msg_ptr_checked(&mut map, first, 16).is_err());
            (*first).buf_len_padded = 1;
            assert!(llmp_next_msg_ptr_checked(&mut map, first, size_of::<LlmpMsg>()).is_err());

            core::ptr::copy_nonoverlapping(
                pattern.as_ptr(),
                llmp_msg_buf_mut_ptr(first),
                pattern.len(),
            );
            for &len in &[0usize, 1, 7, 8, 15, 63, 64, 65, 141] {
                copy_msg_payload_volatile(first, &mut dst, len);
                assert_eq!(&dst[..], &pattern[..len]);
            }
        }
    }

    #[test]
    fn test_llmp_sender_lifecycle_and_reattach() {
        use alloc::format;
        use core::ptr;

        use shmem_providers::NopShMemProvider;

        #[cfg(not(miri))]
        use crate::LLMP_CFG_INITIAL_MAP_SIZE;
        use crate::{
            BrokerId, Flags, LLMP_FLAG_INITIALIZED, LLMP_TAG_END_OF_PAGE, LlmpSender,
            llmp_page_messages_mut_ptr,
        };

        let mut sp = NopShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(sp, ClientId(7), true).unwrap();

        let m = sender.alloc_next(128).unwrap();
        unsafe {
            sender.shrink_alloced(m, 16).unwrap();
            assert!(sender.shrink_alloced(m, 256).is_err());
            let p = sender.out_shmems.last_mut().unwrap().page_mut();
            let saved = ptr::read_volatile(&raw const (*p).size_used);
            ptr::write_volatile(&raw mut (*p).size_used, usize::MAX - 8);
            assert!(sender.shrink_alloced(m, 8).is_err());
            ptr::write_volatile(&raw mut (*p).size_used, saved);
            sender.cancel_send(m);
        }
        assert_eq!(sender.alloc_next(32).unwrap(), m);
        unsafe { sender.reset() };
        let m2 = sender.alloc_next(32).unwrap();
        assert_eq!(m2, m);
        unsafe { sender.cancel_send(m2) };

        sender.send_buf(Tag(0x1111), &[1, 2, 3, 4]).unwrap();
        assert!(sender.describe().unwrap().last_message_offset.is_some());
        assert!(format!("{sender:?}").contains("LlmpSharedMap"));
        #[cfg(not(miri))]
        sender
            .send_buf(Tag(0x2222), &vec![0xAB; LLMP_CFG_INITIAL_MAP_SIZE])
            .unwrap();
        #[cfg(miri)]
        unsafe {
            sender.handle_out_eop().unwrap();
        }
        sender.send_buf(Tag(0x3333), &[9, 8, 7]).unwrap();

        // Recycled page with dirty `broker`/`flags` bytes must reset both on `alloc_next`.
        let mut dirty_map = LlmpSharedMap::new(ClientId(7), sp.new_shmem(4096).unwrap());
        unsafe {
            let first = llmp_page_messages_mut_ptr(dirty_map.page_mut());
            ptr::write_volatile(&raw mut (*first).broker, BrokerId(0xDEAD));
            ptr::write_volatile(&raw mut (*first).flags, Flags(0x7));
            crate::LlmpPage::receiver_joined(dirty_map.page_mut());
            crate::LlmpPage::receiver_left(dirty_map.page_mut());
        }
        let mut recycle_sender = LlmpSender {
            id: ClientId(7),
            last_msg_sent: ptr::null(),
            out_shmems: vec![LlmpSharedMap::new(ClientId(7), sp.new_shmem(4096).unwrap())],
            unused_shmem_cache: vec![dirty_map],
            keep_pages_forever: false,
            has_unsent_message: false,
            shmem_provider: sp,
        };
        unsafe {
            let reused = recycle_sender
                .new_or_unused_shmem(ClientId(7), 1024)
                .unwrap();
            recycle_sender.out_shmems[0] = reused;
            let fresh = recycle_sender.alloc_next(8).unwrap();
            assert_eq!(ptr::read_volatile(&raw const (*fresh).broker), BrokerId(0));
            assert_eq!(
                ptr::read_volatile(&raw const (*fresh).flags),
                LLMP_FLAG_INITIALIZED
            );
            recycle_sender.cancel_send(fresh);
        }

        // Reattaching sender with `None` offset on non-empty page must not clobber msg 1 on EOP.
        let map = LlmpSharedMap::new(ClientId(0), sp.new_shmem(1024).unwrap());
        let mut s1 = LlmpSender::on_existing_shmem(sp, map.shmem, None).unwrap();
        s1.send_buf(Tag(0x1111), &[0x42; 8]).unwrap();
        let mut s2 =
            LlmpSender::on_existing_shmem(sp, s1.out_shmems.pop().unwrap().shmem, None).unwrap();
        unsafe {
            let eop = s2.alloc_eop().unwrap();
            let msg1 = llmp_page_messages_mut_ptr(s2.out_shmems[0].page_mut());
            assert_ne!(eop, msg1);
            assert_eq!((*msg1).tag, Tag(0x1111));
            assert_eq!((*eop).tag, LLMP_TAG_END_OF_PAGE);
            assert_eq!((*eop).message_id.0, (*msg1).message_id.0 + 1);
        }

        let out_map = LlmpSharedMap::new(ClientId(1), sp.new_shmem(1024).unwrap());
        let broker_map = LlmpSharedMap::new(ClientId(0), sp.new_shmem(1024).unwrap());
        let _client =
            LlmpClient::on_existing_shmem(sp, out_map.shmem, None, broker_map.shmem, None).unwrap();
    }

    #[test]
    #[should_panic(
        expected = "The receiver/broker could not process our sent llmp messages in time"
    )]
    fn test_llmp_prune_slow_receiver_panics() {
        use shmem_providers::NopShMemProvider;

        use crate::{EOP_MSG_SIZE, LLMP_CFG_MAX_PENDING_UNREAD_PAGES, LlmpSender};

        let mut sp = NopShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(sp, ClientId(0), false).unwrap();
        sender.out_shmems.clear();
        for _ in 0..=LLMP_CFG_MAX_PENDING_UNREAD_PAGES {
            sender
                .out_shmems
                .push(LlmpSharedMap::new(ClientId(0), sp.new_shmem(1024).unwrap()));
        }
        unsafe {
            let last = sender.out_shmems.last_mut().unwrap().page_mut();
            (*last).size_used = (*last).size_total - EOP_MSG_SIZE;
        }
        sender.alloc_next(16).unwrap();
    }

    #[test]
    fn test_llmp_page_reuse_ordering() {
        use core::sync::atomic::Ordering;
        use std::thread;

        use shmem_providers::NopShMemProvider;

        use crate::{LlmpPage, LlmpSender, llmp_page_messages_mut_ptr};

        #[derive(Copy, Clone)]
        struct SendPagePtr(*mut LlmpPage);
        unsafe impl Send for SendPagePtr {}
        unsafe impl Sync for SendPagePtr {}

        let mut sp = NopShMemProvider::new().unwrap();
        let mut sender = LlmpSender::new(sp, ClientId(0), false).unwrap();
        let active = SendPagePtr(unsafe { sender.out_shmems[0].page_mut() });
        let mut cached = LlmpSharedMap::new(ClientId(0), sp.new_shmem(1024).unwrap());
        cached.mark_safe_to_unmap();
        let cached_ptr = SendPagePtr(unsafe { cached.page_mut() });
        sender.unused_shmem_cache.push(cached);

        thread::scope(|s| {
            s.spawn(move || unsafe {
                let (active, cached_ptr) = (active, cached_ptr);
                LlmpPage::receiver_joined(active.0.cast_const());
                let first = llmp_page_messages_mut_ptr(cached_ptr.0);
                assert_eq!((*first).tag, super::LLMP_TAG_UNSET);
                assert!((*cached_ptr.0).size_total > 0);
                LlmpPage::receiver_left(cached_ptr.0.cast_const());
            });
            unsafe {
                (*active.0).size_used = 64;
                (*active.0).max_alloc_size = 64;
                while (*cached_ptr.0).receivers_left_count.load(Ordering::Relaxed) == 0 {
                    core::hint::spin_loop();
                }
                let reused = sender.new_or_unused_shmem(ClientId(0), 512).unwrap();
                assert_eq!(reused.page(), cached_ptr.0.cast_const());
                assert!(sender.unused_shmem_cache.is_empty());
            }
        });
    }

    #[test]
    fn test_llmp_broker_hooks_and_forwarding() {
        use alloc::vec::Vec;
        use core::{mem::size_of, num::NonZeroUsize};

        use shmem_providers::NopShMemProvider;
        use tuple_list::tuple_list;

        use crate::{
            Broker, Flags, LLMP_TAG_CLIENT_EXIT, LlmpBroker, LlmpBrokerInner, LlmpHook, LlmpMsg,
            LlmpMsgHookResult, LlmpReceiver, LlmpSender,
        };

        #[derive(Debug)]
        struct TestHook;
        impl<SHM: ShMem, SP: ShMemProvider<ShMem = SHM>> LlmpHook<SHM, SP> for TestHook {
            fn on_new_message(
                &mut self,
                broker_inner: &mut LlmpBrokerInner<SHM, SP>,
                _client_id: ClientId,
                msg_tag: &mut Tag,
                msg_flags: &mut Flags,
                msg: &mut [u8],
                _new_msgs: &mut Vec<(Tag, Flags, Vec<u8>)>,
            ) -> Result<LlmpMsgHookResult, libafl_core::Error> {
                match *msg_tag {
                    Tag(0x1) => Ok(LlmpMsgHookResult::Handled),
                    Tag(0x10) => {
                        for _ in 0..4 {
                            let extra = LlmpSharedMap::new(
                                ClientId(99),
                                broker_inner.shmem_provider.new_shmem(1024).unwrap(),
                            );
                            broker_inner.register_client(extra);
                        }
                        *msg_tag = Tag(0x20);
                        *msg_flags = Flags(0x3);
                        msg[0] ^= 0xFF;
                        Ok(LlmpMsgHookResult::ForwardToClients)
                    }
                    Tag(0x30) => {
                        *broker_inner =
                            LlmpBrokerInner::new(broker_inner.shmem_provider.clone()).unwrap();
                        msg.reverse();
                        Ok(LlmpMsgHookResult::ForwardToClients)
                    }
                    _ => Ok(LlmpMsgHookResult::ForwardToClients),
                }
            }
        }

        let sp = NopShMemProvider::new().unwrap();
        let mut broker = LlmpBroker::new(sp, tuple_list!(TestHook)).unwrap();
        let mut s0 = LlmpSender::new(sp, ClientId(1), true).unwrap();
        s0.send_buf(LLMP_TAG_CLIENT_EXIT, &[]).unwrap();
        s0.send_buf(Tag(0x1), &[0xAA]).unwrap();
        s0.send_buf(Tag(0x10), &[0xAA]).unwrap();
        unsafe {
            let last = s0.last_msg_sent;
            let padded = usize::try_from((*last).buf_len_padded).unwrap();
            let after = last
                .cast_mut()
                .cast::<u8>()
                .add(size_of::<LlmpMsg>() + padded);
            core::ptr::write_bytes(after, 0xFE, 16);
        }
        let mut idle = LlmpSender::new(sp, ClientId(2), true).unwrap();
        broker.inner_mut().add_client(
            LlmpReceiver::on_existing_shmem(sp, s0.out_shmems.pop().unwrap().shmem, None).unwrap(),
        );
        broker.inner_mut().add_client(
            LlmpReceiver::on_existing_shmem(sp, idle.out_shmems.pop().unwrap().shmem, None)
                .unwrap(),
        );
        assert!(broker.broker_once().unwrap());
        unsafe {
            let fwd = broker.inner().llmp_out.last_msg_sent;
            let fwd_pad = usize::try_from((*fwd).buf_len_padded).unwrap();
            let tail = core::slice::from_raw_parts(
                fwd.cast::<u8>().add(size_of::<LlmpMsg>() + 1),
                fwd_pad - 1,
            );
            assert!(tail.iter().all(|&b| b == 0));
        }
        let mut out_rx = LlmpReceiver::on_existing_shmem(
            sp,
            broker.inner_mut().llmp_out.out_shmems.pop().unwrap().shmem,
            None,
        )
        .unwrap();
        let (cid, tag, flags, buf) = out_rx.recv_buf_with_flags().unwrap().unwrap();
        assert_eq!(
            (cid, tag, flags, buf),
            (ClientId(1), Tag(0x20), Flags(0x3), &[0x55][..])
        );

        // Hook replacing `*broker_inner` mid-callback must not UAF `recv_shmem`.
        let mut broker2 = LlmpBroker::new(sp, tuple_list!(TestHook)).unwrap();
        let mut s1 = LlmpSender::new(sp, ClientId(3), true).unwrap();
        s1.send_buf(Tag(0x30), &[1, 2, 3, 4]).unwrap();
        let id = broker2
            .inner_mut()
            .register_client(LlmpSharedMap::existing(s1.out_shmems.pop().unwrap().shmem));
        unsafe { broker2.handle_new_msgs(id).unwrap() };
        let mut out_rx2 = LlmpReceiver::on_existing_shmem(
            sp,
            broker2.inner_mut().llmp_out.out_shmems.pop().unwrap().shmem,
            None,
        )
        .unwrap();
        assert_eq!(out_rx2.recv_buf().unwrap().unwrap().2, &[4, 3, 2, 1]);

        // `announce_client_exit` and `loop_forever` with `exit_cleanly_after = 1`.
        let mut broker3 = LlmpBroker::new(sp, tuple_list!()).unwrap();
        broker3.set_exit_after(NonZeroUsize::new(1).unwrap());
        let mut s2 = LlmpSender::new(sp, ClientId(0), true).unwrap();
        LlmpBrokerInner::announce_client_exit(&mut s2, 0).unwrap();
        broker3.inner_mut().add_client(
            LlmpReceiver::on_existing_shmem(sp, s2.out_shmems.pop().unwrap().shmem, None).unwrap(),
        );
        broker3.loop_forever(None);
        assert!(!broker3.has_clients());
    }

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_llmp_eop_rollover_and_reattach() {
        use core::sync::atomic::Ordering;
        use std::thread;

        use tuple_list::tuple_list;

        use crate::{LLMP_CFG_INITIAL_MAP_SIZE, LlmpBroker, LlmpReceiver, LlmpSender};

        let mut sp = StdShMemProvider::new().unwrap();

        // 1. `recv_blocking` transitions across EOP onto a new page cleanly.
        let mut s_block = LlmpSender::new(sp.clone(), ClientId(0), true).unwrap();
        let desc0 = s_block.out_shmems[0].description();
        unsafe { s_block.handle_out_eop().unwrap() };
        let waiter = thread::spawn(move || unsafe {
            let mut bg = StdShMemProvider::new().unwrap();
            let shm = bg.shmem_from_description(desc0).unwrap();
            let mut rx = LlmpReceiver::on_existing_shmem(bg, shm, None).unwrap();
            assert_eq!((*rx.recv_blocking().unwrap()).tag, Tag(0x7777));
        });
        while unsafe {
            (*s_block.out_shmems[1].page())
                .receivers_joined_count
                .load(Ordering::Acquire)
        } == 0
        {
            core::hint::spin_loop();
        }
        s_block.send_buf(Tag(0x7777), &[0x99]).unwrap();
        waiter.join().unwrap();
        drop(s_block);

        // 2. Repeated receiver/client restart reattachment across 6 rollovers prunes & recycles pages
        //    without inflating `receivers_joined_count` or triggering `LLMP_SLOW_RECEIVER_PANIC`.
        let mut broker = LlmpBroker::with_keep_pages(sp.clone(), tuple_list!(), false).unwrap();
        let init_bcast = LlmpSharedMap::existing(
            sp.clone_ref(&broker.inner().llmp_out.out_shmems[0].shmem)
                .unwrap(),
        );
        let mut client = LlmpClient::new(sp.clone(), init_bcast, ClientId(1)).unwrap();
        let _keep_client_out = sp.clone_ref(&client.sender().out_shmems[0].shmem).unwrap();
        let half_plus = vec![0x42u8; (LLMP_CFG_INITIAL_MAP_SIZE / 2) + 1024];
        for round in 0..6u8 {
            // Reattach both before and after receiving a message on the current page.
            let cdesc = client.describe().unwrap();
            drop(client);
            client = LlmpClient::existing_client_from_description(sp.clone(), &cdesc).unwrap();
            unsafe {
                assert_eq!(
                    (*client.receiver().current_recv_shmem.page())
                        .receivers_joined_count
                        .load(Ordering::Acquire),
                    1
                );
            }
            broker.inner_mut().send_buf(Tag(0x500), &[round]).unwrap();
            assert_eq!(client.recv_buf().unwrap().unwrap().2, &[round]);
            let cdesc2 = client.describe().unwrap();
            drop(client);
            client = LlmpClient::existing_client_from_description(sp.clone(), &cdesc2).unwrap();
            broker.inner_mut().send_buf(Tag(0x501), &half_plus).unwrap();
            assert_eq!(client.recv_buf().unwrap().unwrap().2.len(), half_plus.len());
        }
        drop((client, broker));

        // 3. Multi-receiver hand-over-hand refcounting holds pages until the slowest receiver leaves.
        let mut bcast = LlmpBroker::with_keep_pages(sp.clone(), tuple_list!(), false).unwrap();
        let p0 = bcast.inner().llmp_out.out_shmems[0].description();
        let mut fast = LlmpReceiver::on_existing_shmem(
            sp.clone(),
            sp.shmem_from_description(p0).unwrap(),
            None,
        )
        .unwrap();
        let mut slow = LlmpReceiver::on_existing_shmem(
            sp.clone(),
            sp.shmem_from_description(p0).unwrap(),
            None,
        )
        .unwrap();
        for t in [Tag(0x101), Tag(0x102), Tag(0x103)] {
            bcast.inner_mut().send_buf(t, &half_plus).unwrap();
            assert_eq!(fast.recv_buf().unwrap().unwrap().1, t);
        }
        assert!(bcast.inner().llmp_out.unused_shmem_cache.is_empty());
        for t in [Tag(0x101), Tag(0x102), Tag(0x103)] {
            assert_eq!(slow.recv_buf().unwrap().unwrap().1, t);
        }
        drop((fast, slow, bcast));

        // 4. `new_p2p` works across EOP rollover.
        let mut p2p = LlmpClient::new_p2p(sp, ClientId(8)).unwrap();
        p2p.send_buf(Tag(0x4444), &half_plus).unwrap();
        p2p.send_buf(Tag(0x5555), &half_plus).unwrap();
        assert_eq!(p2p.recv_buf().unwrap().unwrap().1, Tag(0x4444));
        assert_eq!(p2p.recv_buf().unwrap().unwrap().1, Tag(0x5555));
    }

    #[test]
    #[serial]
    #[cfg_attr(miri, ignore)]
    fn test_llmp_tcp_listener_ids_and_keep_pages() {
        use tuple_list::tuple_list;

        use crate::{Listener, LlmpBroker, tcp_bind};

        let mut sp = StdShMemProvider::new().unwrap();
        let listener = tcp_bind(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut broker = LlmpBroker::with_keep_pages(sp.clone(), tuple_list!(), false).unwrap();
        broker
            .inner_mut()
            .launch_listener(Listener::Tcp(listener))
            .unwrap();
        assert!(!broker.inner().llmp_out.keep_pages_forever);

        let b2b_map = LlmpSharedMap::new(ClientId(1), sp.new_shmem(4096).unwrap());
        assert_eq!(broker.inner_mut().register_client(b2b_map), ClientId(1));

        let tcp_client = LlmpClient::create_attach_to_tcp(sp, port).unwrap();
        while broker.inner().llmp_clients.len() < 3 {
            broker.broker_once().unwrap();
            std::thread::yield_now();
        }
        assert_eq!(tcp_client.sender().id(), ClientId(2));
        assert_eq!(broker.inner().llmp_clients.last().unwrap().id, ClientId(2));
    }
}
