/*!
A library for low level message passing

To send new messages, the clients place a new message at the end of their
client_out_map. If the ringbuf is filled up, they start place a
LLMP_AGE_END_OF_PAGE_V1 msg and alloc a new shmap.
Once the broker mapped a page, it flags it save for unmapping.

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

After the broker received a new message for clientN, (clientN_out->current_id
!= last_message->message_id) the broker will copy the message content to its
own, centralized page.

The clients periodically check (current_broadcast_map->current_id !=
last_message->message_id) for new incoming messages. If the page is filled up,
the broker instead creates a new page and places a LLMP_TAG_END_OF_PAGE_V1
message in its queue. The LLMP_TAG_END_PAGE_V1 buf contains the new string to
access the shared map. The clients then switch over to read from that new
current map.

```text
[broker]
  |
[current_broadcast_map]
  |
  |___________________________________
  |_________________                  \
  |                 \                  \
  |                  |                  |
 \|/                \|/                \|/
[client0]        [client1]    ...    [clientN]
```

In the future, if we need zero copy, the current_broadcast_map could instead
list the client_out_map ID an offset for each message. In that case, the clients
also need to create new shmaps once their bufs are filled up.


To use, you will have to create a broker using llmp_broker_new().
Then register some clientloops using llmp_broker_register_threaded_clientloop
(or launch them as seperate processes) and call llmp_broker_run();

*/

use alloc::{string::String, vec::Vec};
use core::{
    cmp::max,
    fmt::Debug,
    mem::size_of,
    ptr, slice,
    sync::atomic::{compiler_fence, Ordering},
    time::Duration,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{
    env, fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
};

#[cfg(all(feature = "std", unix))]
use nix::{
    cmsg_space,
    sys::{
        socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags},
        uio::IoVec,
    },
};

#[cfg(all(feature = "std", unix))]
use std::{
    os::unix::{
        self,
        net::{UnixListener, UnixStream},
        {io::AsRawFd, prelude::RawFd},
    },
};

#[cfg(all(unix, feature = "std"))]
use uds::{UnixListenerExt, UnixSocketAddr, UnixStreamExt};

#[cfg(unix)]
use crate::bolts::os::unix_signals::{c_void, setup_signal_handler, siginfo_t, Handler, Signal};
use crate::{
    bolts::shmem::{ShMem, ShMemDescription},
    Error,
};

/// We'll start off with 256 megabyte maps per fuzzer client
#[cfg(not(feature = "llmp_small_maps"))]
const LLMP_CFG_INITIAL_MAP_SIZE: usize = 1 << 28;
/// If llmp_small_maps is set, we start off with 1 meg.
#[cfg(feature = "llmp_small_maps")]
const LLMP_CFG_INITIAL_MAP_SIZE: usize = 1 << 20;
/// What byte count to align messages to
/// LlmpMsg sizes (including header) will always be rounded up to be a multiple of this value
const LLMP_CFG_ALIGNNMENT: usize = 64;

/// A msg fresh from the press: No tag got sent by the user yet
const LLMP_TAG_UNSET: Tag = 0xDEADAF;
/// This message should not exist yet. Some bug in unsafe code!
const LLMP_TAG_UNINITIALIZED: Tag = 0xA143AF11;
/// The end of page message
/// When receiving this, a new sharedmap needs to be allocated.
const LLMP_TAG_END_OF_PAGE: Tag = 0xAF1E0F1;
/// A new client for this broker got added.
const LLMP_TAG_NEW_SHM_CLIENT: Tag = 0xC11E471;
/// The sender on this map is exiting (if broker exits, clients should exit gracefully);
const LLMP_TAG_EXITING: Tag = 0x13C5171;

/// An env var of this value indicates that the set value was a NULL PTR
const _NULL_ENV_STR: &str = "_NULL";

/// Magic indicating that a got initialized correctly
const PAGE_INITIALIZED_MAGIC: u64 = 0x1A1A1A1A1A1A1AF1;

/// Size of a new page message, header, payload, and alignment
const EOP_MSG_SIZE: usize =
    llmp_align(size_of::<LlmpMsg>() + size_of::<LlmpPayloadSharedMapInfo>());
/// The header length of a llmp page in a shared map (until messages start)
const LLMP_PAGE_HEADER_LEN: usize = size_of::<LlmpPage>();

/// The llmp broker registers a signal handler for cleanups on `SIGINT`.
#[cfg(unix)]
static mut GLOBAL_SIGHANDLER_STATE: LlmpBrokerSignalHandler = LlmpBrokerSignalHandler {
    shutting_down: false,
};

/// TAGs used thorughout llmp
pub type Tag = u32;

/// Abstraction for listeners
#[cfg(feature = "std")]
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

#[cfg(feature = "std")]
pub enum ListenerStream {
    Tcp(TcpStream, SocketAddr),
    #[cfg(unix)]
    Unix(UnixStream, unix::net::SocketAddr),
    Empty(),
}

#[cfg(feature = "std")]
impl Listener {
    fn accept(&self) -> ListenerStream {
        match self {
            Listener::Tcp(inner) => match inner.accept() {
                Ok(res) => ListenerStream::Tcp(res.0, res.1),
                Err(err) => {
                    dbg!("Ignoring failed accept", err);
                    ListenerStream::Empty()
                }
            },
            #[cfg(unix)]
            Listener::Unix(inner) => match inner.accept() {
                Ok(res) => ListenerStream::Unix(res.0, res.1),
                Err(err) => {
                    dbg!("Ignoring failed accept", err);
                    ListenerStream::Empty()
                }
            },
        }
    }
}

/// Get sharedmem from a page
#[inline]
unsafe fn shmem2page_mut<SH: ShMem>(afl_shmem: &mut SH) -> *mut LlmpPage {
    afl_shmem.map_mut().as_mut_ptr() as *mut LlmpPage
}

/// Get sharedmem from a page
#[inline]
unsafe fn shmem2page<SH: ShMem>(afl_shmem: &SH) -> *const LlmpPage {
    afl_shmem.map().as_ptr() as *const LlmpPage
}

/// Return, if a msg is contained in the current page
#[inline]
unsafe fn llmp_msg_in_page(page: *const LlmpPage, msg: *const LlmpMsg) -> bool {
    /* DBG("llmp_msg_in_page %p within %p-%p\n", msg, page, page + page->size_total); */
    (page as *const u8) < msg as *const u8
        && (page as *const u8).add((*page).size_total) > msg as *const u8
}

/// allign to LLMP_CFG_ALIGNNMENT=64 bytes
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

/// Reads the stored message offset for the given env_name (by appending _OFFSET)
/// If the content of the env is _NULL, returns None
#[cfg(feature = "std")]
#[inline]
fn msg_offset_from_env(env_name: &str) -> Result<Option<u64>, Error> {
    let msg_offset_str = env::var(&format!("{}_OFFSET", env_name))?;
    Ok(if msg_offset_str == _NULL_ENV_STR {
        None
    } else {
        Some(msg_offset_str.parse()?)
    })
}

/// In case we don't have enough space, make sure the next page will be large
/// enough. For now, we want to have at least enough space to store 2 of the
/// largest messages we encountered (plus message one new_page message).
#[inline]
fn new_map_size(max_alloc: usize) -> usize {
    max(
        max_alloc * 2 + EOP_MSG_SIZE + LLMP_PAGE_HEADER_LEN,
        LLMP_CFG_INITIAL_MAP_SIZE,
    )
    .next_power_of_two()
}

/// Initialize a new llmp_page. size should be relative to
/// llmp_page->messages
unsafe fn _llmp_page_init<SH: ShMem>(shmem: &mut SH, sender: u32, allow_reinit: bool) {
    let map_size = shmem.map().len();
    let page = shmem2page_mut(shmem);
    if (*page).magic == PAGE_INITIALIZED_MAGIC && !allow_reinit {
        panic!(
            "Tried to initialize page {:?} twice (for shmem {:?})",
            page, shmem
        );
    };
    (*page).magic = PAGE_INITIALIZED_MAGIC;
    (*page).sender = sender;
    ptr::write_volatile(&mut (*page).current_msg_id, 0);
    (*page).max_alloc_size = 0;
    // Don't forget to subtract our own header size
    (*page).size_total = map_size - LLMP_PAGE_HEADER_LEN;
    (*page).size_used = 0;
    (*(*page).messages.as_mut_ptr()).message_id = 0;
    (*(*page).messages.as_mut_ptr()).tag = LLMP_TAG_UNSET;
    ptr::write_volatile(&mut (*page).save_to_unmap, 0);
    ptr::write_volatile(&mut (*page).sender_dead, 0);
}

/// Get the next pointer and make sure it's in the current page, and has enough space.
#[inline]
unsafe fn llmp_next_msg_ptr_checked<SH: ShMem>(
    map: &mut LlmpSharedMap<SH>,
    last_msg: *const LlmpMsg,
    alloc_size: usize,
) -> Result<*mut LlmpMsg, Error> {
    let page = map.page_mut();
    let map_size = map.shmem.map().len();
    let msg_begin_min = (page as *const u8).add(size_of::<LlmpPage>());
    // We still need space for this msg (alloc_size).
    let msg_begin_max = (page as *const u8).add(map_size - alloc_size);
    let next = _llmp_next_msg_ptr(last_msg);
    let next_ptr = next as *const u8;
    if next_ptr >= msg_begin_min && next_ptr <= msg_begin_max {
        Ok(next)
    } else {
        Err(Error::IllegalState(format!(
            "Inconsistent data on sharedmap, or Bug (next_ptr was {:x}, sharedmap page was {:x})",
            next_ptr as usize, page as usize
        )))
    }
}

/// Pointer to the message behind the last message
#[inline]
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
    /// Info about the SharedMap in use
    shmem: ShMemDescription,
    /// The last message sent or received, depnding on page type
    last_message_offset: Option<u64>,
}

#[derive(Copy, Clone, Debug)]
/// Result of an LLMP Mesasge hook
pub enum LlmpMsgHookResult {
    /// This has been handled in the broker. No need to forward.
    Handled,
    /// Forward this to the clients. We are not done here.
    ForwardToClients,
}

/// Message sent over the "wire"
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct LlmpMsg {
    /// A tag
    pub tag: Tag,
    /// Sender of this messge
    pub sender: u32,
    /// The message ID, unique per page
    pub message_id: u64,
    /// Buffer length as specified by the user
    pub buf_len: u64,
    /// (Actual) buffer length after padding
    pub buf_len_padded: u64,
    /// The buf
    pub buf: [u8; 0],
}

/// The message we receive
impl LlmpMsg {
    /// Gets the buffer from this message as slice, with the corrent length.
    /// # Safety
    /// This is unsafe if somebody has access to shared mem pages on the system.
    pub unsafe fn as_slice_unsafe(&self) -> &[u8] {
        slice::from_raw_parts(self.buf.as_ptr(), self.buf_len as usize)
    }

    /// Gets the buffer from this message as slice, with the corrent length.
    #[inline]
    pub fn as_slice<SH: ShMem>(&self, map: &mut LlmpSharedMap<SH>) -> Result<&[u8], Error> {
        unsafe {
            if self.in_map(map) {
                Ok(self.as_slice_unsafe())
            } else {
                Err(Error::IllegalState("Current message not in page. The sharedmap get tampered with or we have a BUG.".into()))
            }
        }
    }

    /// Returns true, if the pointer is, indeed, in the page of this shared map.
    #[inline]
    pub fn in_map<SH: ShMem>(&self, map: &mut LlmpSharedMap<SH>) -> bool {
        unsafe {
            let map_size = map.shmem.map().len();
            let buf_ptr = self.buf.as_ptr();
            if buf_ptr > (map.page_mut() as *const u8).add(size_of::<LlmpPage>())
                && buf_ptr
                    <= (map.page_mut() as *const u8).add(map_size - size_of::<LlmpMsg>() as usize)
            {
                // The message header is in the page. Continue with checking the body.
                let len = self.buf_len_padded as usize + size_of::<LlmpMsg>();
                buf_ptr <= (map.page_mut() as *const u8).add(map_size - len)
            } else {
                false
            }
        }
    }
}

/// An Llmp instance
#[derive(Clone, Debug)]
pub enum LlmpConnection<SH>
where
    SH: ShMem,
{
    /// A broker and a thread using this tcp background thread
    IsBroker { broker: LlmpBroker<SH> },
    /// A client, connected to the port
    IsClient { client: LlmpClient<SH> },
}

impl<SH> LlmpConnection<SH>
where
    SH: ShMem,
{
    #[cfg(feature = "std")]
    /// Creates either a broker, if the tcp port is not bound, or a client, connected to this port.
    pub fn on_port(port: u16) -> Result<Self, Error> {
        match TcpListener::bind(format!("127.0.0.1:{}", port)) {
            Ok(listener) => {
                // We got the port. We are the broker! :)
                dbg!("We're the broker");
                let mut broker = LlmpBroker::new()?;
                let _listener_thread = broker.launch_listener(Listener::Tcp(listener))?;
                Ok(LlmpConnection::IsBroker { broker })
            }
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::AddrInUse => {
                        // We are the client :)
                        dbg!("We're the client", e);
                        Ok(LlmpConnection::IsClient {
                            client: LlmpClient::create_attach_to_tcp(port)?,
                        })
                    }
                    _ => Err(Error::File(e)),
                }
            }
        }
    }

    /// Describe this in a reproducable fashion, if it's a client
    pub fn describe(&self) -> Result<LlmpClientDescription, Error> {
        Ok(match self {
            LlmpConnection::IsClient { client } => client.describe()?,
            _ => todo!("Only client can be described atm."),
        })
    }

    /// Recreate an existing client from the stored description
    pub fn existing_client_from_description(
        description: &LlmpClientDescription,
    ) -> Result<LlmpConnection<SH>, Error> {
        Ok(LlmpConnection::IsClient {
            client: LlmpClient::existing_client_from_description(description)?,
        })
    }

    /// Sends the given buffer over this connection, no matter if client or broker.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        match self {
            LlmpConnection::IsBroker { broker } => broker.send_buf(tag, buf),
            LlmpConnection::IsClient { client } => client.send_buf(tag, buf),
        }
    }
}

#[cfg(all(unix, feature = "std"))]
impl<SH> LlmpConnection<SH>
where
    SH: ShMem,
{
    #[cfg(all(feature = "std", unix))]
    pub fn on_domain_socket(filename: &str) -> Result<Self, Error> {
        match UnixListener::bind_unix_addr(&UnixSocketAddr::new(filename).unwrap()) {
            Ok(listener) => {
                dbg!("We're the broker");
                let mut broker = LlmpBroker::new()?;
                broker.socket_name = Some(filename.to_string());
                let _listener_thread = broker.launch_listener(Listener::Unix(listener))?;
                Ok(LlmpConnection::IsBroker { broker })
            }
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::AddrInUse => {
                        // We are the client :)
                        dbg!("We're the client", e);
                        Ok(LlmpConnection::IsClient {
                            client: LlmpClient::create_attach_to_unix(filename)?,
                        })
                    }
                    _ => Err(Error::File(e)),
                }
            }
        }
    }
}

/// Contents of the share mem pages, used by llmp internally
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct LlmpPage {
    /// to check if this page got initialized properly
    pub magic: u64,
    /// The id of the sender
    pub sender: u32,
    /// Set to != 1 by the receiver, once it got mapped
    /// It's not safe for the sender to unmap this page before
    /// (The os may have tidied up the memory when the receiver starts to map)
    pub save_to_unmap: u16,
    /// Not used at the moment (would indicate that the sender is no longer there)
    pub sender_dead: u16,
    /// The current message ID
    pub current_msg_id: u64,
    /// How much space is available on this page in bytes
    pub size_total: usize,
    /// How much space is used on this page in bytes
    pub size_used: usize,
    /// The maximum amount of bytes that ever got allocated on this page in one go
    /// An inidactor of what to use as size for future pages
    pub max_alloc_size: usize,
    /// Pointer to the messages, from here on.
    pub messages: [LlmpMsg; 0],
}

/// Message payload when a client got added LLMP_TAG_CLIENT_ADDED_V1 */
/// This is an internal message!
/// LLMP_TAG_END_OF_PAGE_V1
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct LlmpPayloadSharedMapInfo {
    /// The map size
    pub map_size: usize,
    /// The id of this map, as 0-terminated c string of at most 19 chars
    pub shm_str: [u8; 20],
}

/// Sending end on a (unidirectional) sharedmap channel
#[derive(Clone, Debug)]
pub struct LlmpSender<SH>
where
    SH: ShMem,
{
    /// ID of this sender. Only used in the broker.
    pub id: u32,
    /// Ref to the last message this sender sent on the last page.
    /// If null, a new page (just) started.
    pub last_msg_sent: *const LlmpMsg,
    /// A vec of page wrappers, each containing an intialized AfShmem
    pub out_maps: Vec<LlmpSharedMap<SH>>,
    /// If true, pages will never be pruned.
    /// The broker uses this feature.
    /// By keeping the message history around,
    /// new clients may join at any time in the future.
    pub keep_pages_forever: bool,
}

/// An actor on the sendin part of the shared map
impl<SH> LlmpSender<SH>
where
    SH: ShMem,
{
    pub fn new(id: u32, keep_pages_forever: bool) -> Result<Self, Error> {
        Ok(Self {
            id,
            last_msg_sent: ptr::null_mut(),
            out_maps: vec![LlmpSharedMap::new(
                0,
                SH::new_map(new_map_size(LLMP_CFG_INITIAL_MAP_SIZE))?,
            )],
            // drop pages to the broker if it already read them
            keep_pages_forever,
        })
    }

    /// Completely reset the current sender map.
    /// Afterwards, no receiver should read from it at a different location.
    /// This is only useful if all connected llmp parties start over, for example after a crash.
    /// # Safety
    /// Only safe if you really really restart the page on everything connected
    pub unsafe fn reset(&mut self) {
        _llmp_page_init(&mut self.out_maps.last_mut().unwrap().shmem, self.id, true);
        self.last_msg_sent = ptr::null_mut();
    }

    /// Reattach to a vacant out_map, to with a previous sender stored the information in an env before.
    #[cfg(feature = "std")]
    pub fn on_existing_from_env(env_name: &str) -> Result<Self, Error> {
        let msg_sent_offset = msg_offset_from_env(env_name)?;
        Self::on_existing_map(SH::existing_from_env(env_name)?, msg_sent_offset)
    }

    /// Store the info to this sender to env.
    /// A new client can reattach to it using on_existing_from_env
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) -> Result<(), Error> {
        let current_out_map = self.out_maps.last().unwrap();
        current_out_map.shmem.write_to_env(env_name)?;
        unsafe { current_out_map.msg_to_env(self.last_msg_sent, env_name) }
    }

    /// Waits for this sender to be save to unmap.
    /// If a receiver is involved, this function should always be called.
    pub fn await_save_to_unmap_blocking(&self) {
        loop {
            if self.save_to_unmap() {
                return;
            }
        }
    }

    /// If we are allowed to unmap this client
    pub fn save_to_unmap(&self) -> bool {
        let current_out_map = self.out_maps.last().unwrap();
        unsafe {
            compiler_fence(Ordering::SeqCst);
            // println!("Reading save_to_unmap from {:?}", current_out_map.page() as *const _);
            ptr::read_volatile(&(*current_out_map.page()).save_to_unmap) != 0
        }
    }

    /// Reattach to a vacant out_map.
    /// It is essential, that the receiver (or someone else) keeps a pointer to this map
    /// else reattach will get a new, empty page, from the OS, or fail.
    pub fn on_existing_map(
        current_out_map: SH,
        last_msg_sent_offset: Option<u64>,
    ) -> Result<Self, Error> {
        let mut out_map = LlmpSharedMap::existing(current_out_map);
        let last_msg_sent = match last_msg_sent_offset {
            Some(offset) => out_map.msg_from_offset(offset)?,
            None => ptr::null_mut(),
        };

        Ok(Self {
            id: 0,
            last_msg_sent,
            out_maps: vec![out_map],
            // drop pages to the broker if it already read them
            keep_pages_forever: false,
        })
    }

    /// For non zero-copy, we want to get rid of old pages with duplicate messages in the client
    /// eventually. This function This funtion sees if we can unallocate older pages.
    /// The broker would have informed us by setting the save_to_unmap-flag.
    unsafe fn prune_old_pages(&mut self) {
        // Exclude the current page by splitting of the last element for this iter
        let mut unmap_until_excl = 0;
        for map in self.out_maps.split_last_mut().unwrap().1 {
            if (*map.page_mut()).save_to_unmap == 0 {
                // The broker didn't read this page yet, no more pages to unmap.
                break;
            }
            unmap_until_excl += 1;
        }
        // Remove all maps that the broker already mapped
        // simply removing them from the vec should then call drop and unmap them.
        self.out_maps.drain(0..unmap_until_excl);
    }

    /// Intern: Special allocation function for EOP messages (and nothing else!)
    /// The normal alloc will fail if there is not enough space for buf_len_padded + EOP
    /// So if alloc_next fails, create new page if necessary, use this function,
    /// place EOP, commit EOP, reset, alloc again on the new space.
    unsafe fn alloc_eop(&mut self) -> Result<*mut LlmpMsg, Error> {
        let mut map = self.out_maps.last_mut().unwrap();
        let page = map.page_mut();
        let last_msg = self.last_msg_sent;
        if (*page).size_used + EOP_MSG_SIZE > (*page).size_total {
            panic!("PROGRAM ABORT : BUG: EOP does not fit in page! page {:?}, size_current {:?}, size_total {:?}", page,
                (*page).size_used, (*page).size_total);
        }
        let mut ret: *mut LlmpMsg = if !last_msg.is_null() {
            llmp_next_msg_ptr_checked(&mut map, last_msg, EOP_MSG_SIZE)?
        } else {
            (*page).messages.as_mut_ptr()
        };
        if (*ret).tag == LLMP_TAG_UNINITIALIZED {
            panic!("Did not call send() on last message!");
        }
        (*ret).buf_len_padded = size_of::<LlmpPayloadSharedMapInfo>() as u64;
        (*ret).message_id = if !last_msg.is_null() {
            (*last_msg).message_id + 1
        } else {
            1
        };
        (*ret).tag = LLMP_TAG_END_OF_PAGE;
        (*page).size_used += EOP_MSG_SIZE;
        Ok(ret)
    }

    /// Intern: Will return a ptr to the next msg buf, or None if map is full.
    /// Never call alloc_next without either sending or cancelling the last allocated message for this page!
    /// There can only ever be up to one message allocated per page at each given time.
    unsafe fn alloc_next_if_space(&mut self, buf_len: usize) -> Option<*mut LlmpMsg> {
        let buf_len_padded;
        let mut complete_msg_size = llmp_align(size_of::<LlmpMsg>() + buf_len);
        let map = self.out_maps.last_mut().unwrap();
        let page = map.page_mut();
        let last_msg = self.last_msg_sent;
        /* DBG("XXX complete_msg_size %lu (h: %lu)\n", complete_msg_size, sizeof(llmp_message)); */
        /* In case we don't have enough space, make sure the next page will be large
         * enough */
        // For future allocs, keep track of the maximum (aligned) alloc size we used
        (*page).max_alloc_size = max((*page).max_alloc_size, complete_msg_size);

        let mut ret: *mut LlmpMsg;
        /* DBG("last_msg %p %d (%d)\n", last_msg, last_msg ? (int)last_msg->tag : -1, (int)LLMP_TAG_END_OF_PAGE_V1); */
        if last_msg.is_null() || (*last_msg).tag == LLMP_TAG_END_OF_PAGE {
            /* We start fresh, on a new page */
            ret = (*page).messages.as_mut_ptr();
            /* The initial message may not be alligned, so we at least align the end of
            it. Technically, c_ulong can be smaller than a pointer, then who knows what
            happens */
            let base_addr = ret as usize;
            buf_len_padded =
                llmp_align(base_addr + complete_msg_size) - base_addr - size_of::<LlmpMsg>();
            complete_msg_size = buf_len_padded + size_of::<LlmpMsg>();
            /* DBG("XXX complete_msg_size NEW %lu\n", complete_msg_size); */
            /* Still space for the new message plus the additional "we're full" message?
             */
            if (*page).size_used + complete_msg_size + EOP_MSG_SIZE > (*page).size_total {
                /* We're full. */
                return None;
            }
            /* We need to start with 1 for ids, as current message id is initialized
             * with 0... */
            (*ret).message_id = if !last_msg.is_null() {
                (*last_msg).message_id + 1
            } else {
                1
            }
        } else if (*page).current_msg_id != (*last_msg).message_id {
            /* Oops, wrong usage! */
            panic!("BUG: The current message never got commited using send! (page->current_msg_id {:?}, last_msg->message_id: {})", (*page).current_msg_id, (*last_msg).message_id);
        } else {
            buf_len_padded = complete_msg_size - size_of::<LlmpMsg>();
            /* DBG("XXX ret %p id %u buf_len_padded %lu complete_msg_size %lu\n", ret, ret->message_id, buf_len_padded,
             * complete_msg_size); */

            /* Still space for the new message plus the additional "we're full" message? */
            if (*page).size_used + complete_msg_size + EOP_MSG_SIZE > (*page).size_total {
                /* We're full. */
                return None;
            }
            ret = match llmp_next_msg_ptr_checked(map, last_msg, complete_msg_size) {
                Ok(msg) => msg,
                Err(e) => {
                    #[cfg(feature = "std")]
                    dbg!("Unexpected error allocing new msg", e);
                    #[cfg(feature = "std")]
                    return None;
                    #[cfg(not(feature = "std"))]
                    panic!(&format!("Unexpected error allocing new msg {:?}", e));
                }
            };
            (*ret).message_id = (*last_msg).message_id + 1
        }

        /* The beginning of our message should be messages + size_used, else nobody
         * sent the last msg! */
        /* DBG("XXX ret %p - page->messages %p = %lu != %lu, will add %lu -> %p\n", ret, page->messages,
        (c_ulong)((u8 *)ret - (u8 *)page->messages), page->size_used, complete_msg_size, ((u8 *)ret) + complete_msg_size);
        */

        if last_msg.is_null() && (*page).size_used != 0
            || ((ret as usize) - (*page).messages.as_mut_ptr() as usize) != (*page).size_used
        {
            panic!("Allocated new message without calling send() inbetween. ret: {:?}, page: {:?}, complete_msg_size: {:?}, size_used: {:?}, last_msg: {:?}", ret, page,
                buf_len_padded, (*page).size_used, last_msg);
        }
        (*page).size_used += complete_msg_size;
        (*ret).buf_len_padded = buf_len_padded as u64;
        (*ret).buf_len = buf_len as u64;
        /* DBG("Returning new message at %p with len %ld, TAG was %x", ret, ret->buf_len_padded, ret->tag); */
        /* Maybe catch some bugs... */
        (*_llmp_next_msg_ptr(ret)).tag = LLMP_TAG_UNSET;
        (*ret).tag = LLMP_TAG_UNINITIALIZED;
        Some(ret)
    }

    /// Commit the message last allocated by alloc_next to the queue.
    /// After commiting, the msg shall no longer be altered!
    /// It will be read by the consuming threads (broker->clients or client->broker)
    #[inline(never)] // Not inlined to make cpu-level reodering (hopefully?) improbable
    unsafe fn send(&mut self, msg: *mut LlmpMsg) -> Result<(), Error> {
        if self.last_msg_sent == msg {
            panic!("Message sent twice!");
        }
        if (*msg).tag == LLMP_TAG_UNSET {
            panic!("No tag set on message with id {}", (*msg).message_id);
        }
        let page = self.out_maps.last_mut().unwrap().page_mut();
        if msg.is_null() || !llmp_msg_in_page(page, msg) {
            return Err(Error::Unknown(format!(
                "Llmp Message {:?} is null or not in current page",
                msg
            )));
        }
        (*msg).message_id = (*page).current_msg_id + 1;
        compiler_fence(Ordering::SeqCst);
        ptr::write_volatile(&mut (*page).current_msg_id, (*msg).message_id);
        compiler_fence(Ordering::SeqCst);
        self.last_msg_sent = msg;
        Ok(())
    }

    /// listener about it using a EOP message.
    unsafe fn handle_out_eop(&mut self) -> Result<(), Error> {
        let old_map = self.out_maps.last_mut().unwrap().page_mut();

        // Create a new shard page.
        let mut new_map_shmem = LlmpSharedMap::new(
            (*old_map).sender,
            SH::new_map(new_map_size((*old_map).max_alloc_size))?,
        );
        let mut new_map = new_map_shmem.page_mut();

        ptr::write_volatile(&mut (*new_map).current_msg_id, (*old_map).current_msg_id);
        (*new_map).max_alloc_size = (*old_map).max_alloc_size;
        /* On the old map, place a last message linking to the new map for the clients
         * to consume */
        let mut out: *mut LlmpMsg = self.alloc_eop()?;
        (*out).sender = (*old_map).sender;

        let mut end_of_page_msg = (*out).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;
        (*end_of_page_msg).map_size = new_map_shmem.shmem.map().len();
        (*end_of_page_msg).shm_str = *new_map_shmem.shmem.shm_slice();

        // We never sent a msg on the new buf */
        self.last_msg_sent = ptr::null_mut();

        /* Send the last msg on the old buf */
        self.send(out)?;

        if !self.keep_pages_forever {
            self.prune_old_pages();
        }

        self.out_maps.push(new_map_shmem);

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

        match unsafe { self.alloc_next_if_space(buf_len) } {
            Some(msg) => Ok(msg),
            None => Err(Error::Unknown(format!(
                "Error allocating {} bytes in shmap",
                buf_len
            ))),
        }
    }

    /// Cancel send of the next message, this allows us to allocate a new message without sending this one.
    /// # Safety
    /// They msg pointer may no longer be used after `cancel_send`
    pub unsafe fn cancel_send(&mut self, msg: *mut LlmpMsg) {
        /* DBG("Client %d cancels send of msg at %p with tag 0x%X and size %ld", client->id, msg, msg->tag,
         * msg->buf_len_padded); */
        let page = self.out_maps.last_mut().unwrap().page_mut();
        (*msg).tag = LLMP_TAG_UNSET;
        (*page).size_used -= (*msg).buf_len_padded as usize + size_of::<LlmpMsg>();
    }

    /// Allocates a message of the given size, tags it, and sends it off.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        // Make sure we don't reuse already allocated tags
        if tag == LLMP_TAG_NEW_SHM_CLIENT
            || tag == LLMP_TAG_END_OF_PAGE
            || tag == LLMP_TAG_UNINITIALIZED
            || tag == LLMP_TAG_UNSET
        {
            return Err(Error::Unknown(format!(
                "Reserved tag supplied to send_buf ({:#X})",
                tag
            )));
        }

        unsafe {
            let msg = self.alloc_next(buf.len())?;
            (*msg).tag = tag;
            buf.as_ptr()
                .copy_to_nonoverlapping((*msg).buf.as_mut_ptr(), buf.len());
            self.send(msg)
        }
    }

    // Describe this cient in a way, that it can be restored later with `Self::on_existing_from_description`
    pub fn describe(&self) -> Result<LlmpDescription, Error> {
        let map = self.out_maps.last().unwrap();
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

    // Create this client on an existing map from the given description. acquired with `self.describe`
    pub fn on_existing_from_description(description: &LlmpDescription) -> Result<Self, Error> {
        Self::on_existing_map(
            SH::existing_from_description(&description.shmem)?,
            description.last_message_offset,
        )
    }
}

/// Receiving end on a (unidirectional) sharedmap channel
#[derive(Clone, Debug)]
pub struct LlmpReceiver<SH>
where
    SH: ShMem,
{
    pub id: u32,
    /// Pointer to the last meg this received
    pub last_msg_recvd: *const LlmpMsg,
    /// current page. After EOP, this gets replaced with the new one
    pub current_recv_map: LlmpSharedMap<SH>,
}

/// Receiving end of an llmp channel
impl<SH> LlmpReceiver<SH>
where
    SH: ShMem,
{
    /// Reattach to a vacant recv_map, to with a previous sender stored the information in an env before.
    #[cfg(feature = "std")]
    pub fn on_existing_from_env(env_name: &str) -> Result<Self, Error> {
        Self::on_existing_map(
            SH::existing_from_env(env_name)?,
            msg_offset_from_env(env_name)?,
        )
    }

    /// Store the info to this receiver to env.
    /// A new client can reattach to it using on_existing_from_env
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) -> Result<(), Error> {
        let current_out_map = &self.current_recv_map;
        current_out_map.shmem.write_to_env(env_name)?;
        unsafe { current_out_map.msg_to_env(self.last_msg_recvd, env_name) }
    }

    /// Create a Receiver, reattaching to an existing sender map.
    /// It is essential, that the sender (or someone else) keeps a pointer to the sender_map
    /// else reattach will get a new, empty page, from the OS, or fail.
    pub fn on_existing_map(
        current_sender_map: SH,
        last_msg_recvd_offset: Option<u64>,
    ) -> Result<Self, Error> {
        let mut current_recv_map = LlmpSharedMap::existing(current_sender_map);
        let last_msg_recvd = match last_msg_recvd_offset {
            Some(offset) => current_recv_map.msg_from_offset(offset)?,
            None => ptr::null_mut(),
        };

        Ok(Self {
            id: 0,
            current_recv_map,
            last_msg_recvd,
        })
    }

    // Never inline, to not get some strange effects
    /// Read next message.
    #[inline(never)]
    unsafe fn recv(&mut self) -> Result<Option<*mut LlmpMsg>, Error> {
        /* DBG("recv %p %p\n", page, last_msg); */
        compiler_fence(Ordering::SeqCst);
        let mut page = self.current_recv_map.page_mut();
        let last_msg = self.last_msg_recvd;
        let current_msg_id = ptr::read_volatile(&(*page).current_msg_id);

        // Read the message from the page
        let ret = if current_msg_id == 0 {
            /* No messages yet */
            None
        } else if last_msg.is_null() {
            /* We never read a message from this queue. Return first. */
            Some((*page).messages.as_mut_ptr())
        } else if (*last_msg).message_id == current_msg_id {
            /* Oops! No new message! */
            None
        } else {
            // We don't know how big the msg wants to be, assert at least the header has space.
            Some(llmp_next_msg_ptr_checked(
                &mut self.current_recv_map,
                last_msg,
                size_of::<LlmpMsg>(),
            )?)
        };

        // Let's see what we go here.
        if let Some(msg) = ret {
            if !(*msg).in_map(&mut self.current_recv_map) {
                return Err(Error::IllegalState("Unexpected message in map (out of map bounds) - bugy client or tampered shared map detedted!".into()));
            }
            // Handle special, LLMP internal, messages.
            match (*msg).tag {
                LLMP_TAG_UNSET => panic!("BUG: Read unallocated msg"),
                LLMP_TAG_EXITING => {
                    // The other side is done.
                    assert_eq!((*msg).buf_len, 0);
                    return Err(Error::ShuttingDown);
                }
                LLMP_TAG_END_OF_PAGE => {
                    #[cfg(feature = "std")]
                    println!("Received end of page, allocating next");
                    // Handle end of page
                    if (*msg).buf_len < size_of::<LlmpPayloadSharedMapInfo>() as u64 {
                        panic!(
                            "Illegal message length for EOP (is {}, expected {})",
                            (*msg).buf_len_padded,
                            size_of::<LlmpPayloadSharedMapInfo>()
                        );
                    }
                    let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;

                    /* The pageinfo points to the map we're about to unmap.
                    Copy the contents first to be safe (probably fine in rust either way). */
                    let pageinfo_cpy = *pageinfo;

                    // Mark the old page save to unmap, in case we didn't so earlier.
                    ptr::write_volatile(&mut (*page).save_to_unmap, 1);

                    // Map the new page. The old one should be unmapped by Drop
                    self.current_recv_map = LlmpSharedMap::existing(SH::existing_from_shm_slice(
                        &pageinfo_cpy.shm_str,
                        pageinfo_cpy.map_size,
                    )?);
                    page = self.current_recv_map.page_mut();
                    // Mark the new page save to unmap also (it's mapped by us, the broker now)
                    ptr::write_volatile(&mut (*page).save_to_unmap, 1);

                    #[cfg(feature = "std")]
                    dbg!("Got a new recv map", self.current_recv_map.shmem.shm_str());
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
        let mut current_msg_id = 0;
        let page = self.current_recv_map.page_mut();
        let last_msg = self.last_msg_recvd;
        if !last_msg.is_null() {
            if (*last_msg).tag == LLMP_TAG_END_OF_PAGE && !llmp_msg_in_page(page, last_msg) {
                panic!("BUG: full page passed to await_message_blocking or reset failed");
            }
            current_msg_id = (*last_msg).message_id
        }
        loop {
            compiler_fence(Ordering::SeqCst);
            if ptr::read_volatile(&(*page).current_msg_id) != current_msg_id {
                return match self.recv()? {
                    Some(msg) => Ok(msg),
                    None => panic!("BUG: blocking llmp message should never be NULL"),
                };
            }
        }
    }

    /// Returns the next message, tag, buf, if avaliable, else None
    #[inline]
    pub fn recv_buf(&mut self) -> Result<Option<(u32, u32, &[u8])>, Error> {
        unsafe {
            Ok(match self.recv()? {
                Some(msg) => Some((
                    (*msg).sender,
                    (*msg).tag,
                    (*msg).as_slice(&mut self.current_recv_map)?,
                )),
                None => None,
            })
        }
    }

    /// Returns the next sender, tag, buf, looping until it becomes available
    #[inline]
    pub fn recv_buf_blocking(&mut self) -> Result<(u32, u32, &[u8]), Error> {
        unsafe {
            let msg = self.recv_blocking()?;
            Ok((
                (*msg).sender,
                (*msg).tag,
                (*msg).as_slice(&mut self.current_recv_map)?,
            ))
        }
    }

    // Describe this cient in a way, that it can be restored later with `Self::on_existing_from_description`
    pub fn describe(&self) -> Result<LlmpDescription, Error> {
        let map = &self.current_recv_map;
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

    // Create this client on an existing map from the given description. acquired with `self.describe`
    pub fn on_existing_from_description(description: &LlmpDescription) -> Result<Self, Error> {
        Self::on_existing_map(
            SH::existing_from_description(&description.shmem)?,
            description.last_message_offset,
        )
    }
}

/// A page wrapper
#[derive(Clone, Debug)]
pub struct LlmpSharedMap<SH>
where
    SH: ShMem,
{
    /// Shmem containg the actual (unsafe) page,
    /// shared between one LlmpSender and one LlmpReceiver
    pub shmem: SH,
}

// TODO: May be obsolete
/// The page struct, placed on a shared mem instance.
/// A thin wrapper around a ShMem implementation, with special Llmp funcs
impl<SH> LlmpSharedMap<SH>
where
    SH: ShMem,
{
    /// Creates a new page, initializing the passed shared mem struct
    pub fn new(sender: u32, mut new_map: SH) -> Self {
        unsafe {
            _llmp_page_init(&mut new_map, sender, false);
        }
        Self { shmem: new_map }
    }

    /// Maps and wraps an existing
    pub fn existing(existing_map: SH) -> Self {
        let ret = Self {
            shmem: existing_map,
        };
        unsafe {
            if (*ret.page()).magic != PAGE_INITIALIZED_MAGIC {
                panic!("Map was not priviously initialized at {:?}", &ret.shmem);
            }
        }
        ret
    }

    /// Marks the containing page as `save_to_unmap`.
    /// This indicates, that the page may safely be unmapped by the sender.
    pub fn mark_save_to_unmap(&mut self) {
        unsafe {
            ptr::write_volatile(&mut (*self.page_mut()).save_to_unmap, 1);
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
    /// Will return IllegalArgument error if msg is not on page.
    /// # Safety
    /// This dereferences msg, make sure to pass a proper pointer to it.
    pub unsafe fn msg_to_offset(&self, msg: *const LlmpMsg) -> Result<u64, Error> {
        let page = self.page();
        if llmp_msg_in_page(page, msg) {
            // Cast both sides to u8 arrays, get the offset, then cast the return isize to u64
            Ok((msg as *const u8).offset_from((*page).messages.as_ptr() as *const u8) as u64)
        } else {
            Err(Error::IllegalArgument(format!(
                "Message (0x{:X}) not in page (0x{:X})",
                page as u64, msg as u64
            )))
        }
    }

    /// Retrieve the stored msg from env_name + _OFFSET.
    /// It will restore the stored offset by env_name and return the message.
    #[cfg(feature = "std")]
    pub fn msg_from_env(&mut self, map_env_name: &str) -> Result<*mut LlmpMsg, Error> {
        match msg_offset_from_env(map_env_name)? {
            Some(offset) => self.msg_from_offset(offset),
            None => Ok(ptr::null_mut()),
        }
    }

    /// Store this msg offset to env_name + _OFFSET env variable.
    /// It can be restored using msg_from_env with the same env_name later.
    /// # Safety
    /// This function will dereference the msg ptr, make sure it's valid.
    #[cfg(feature = "std")]
    pub unsafe fn msg_to_env(&self, msg: *const LlmpMsg, map_env_name: &str) -> Result<(), Error> {
        if msg.is_null() {
            env::set_var(&format!("{}_OFFSET", map_env_name), _NULL_ENV_STR)
        } else {
            env::set_var(
                &format!("{}_OFFSET", map_env_name),
                format!("{}", self.msg_to_offset(msg)?),
            )
        };
        Ok(())
    }

    /// Gets this message from this page, at the indicated offset.
    /// Will return IllegalArgument error if the offset is out of bounds.
    pub fn msg_from_offset(&mut self, offset: u64) -> Result<*mut LlmpMsg, Error> {
        unsafe {
            let page = self.page_mut();
            let page_size = self.shmem.map().len() - size_of::<LlmpPage>();
            if offset as isize > page_size as isize {
                Err(Error::IllegalArgument(format!(
                    "Msg offset out of bounds (size: {}, requested offset: {})",
                    page_size, offset
                )))
            } else {
                Ok(
                    ((*page).messages.as_mut_ptr() as *mut u8).offset(offset as isize)
                        as *mut LlmpMsg,
                )
            }
        }
    }
}

/// The broker (node 0)
#[derive(Clone, Debug)]
pub struct LlmpBroker<SH>
where
    SH: ShMem,
{
    /// Broadcast map from broker to all clients
    pub llmp_out: LlmpSender<SH>,
    /// Users of Llmp can add message handlers in the broker.
    /// This allows us to intercept messages right in the broker
    /// This keeps the out map clean.
    pub llmp_clients: Vec<LlmpReceiver<SH>>,
    /// This is the socket name, when unix domain sockets are used.
    socket_name: Option<String>,
    /// This flag is used to indicate that shutdown has been requested by the SIGINT and SIGTERM
    /// handlers
    shutting_down: bool,
}

#[cfg(unix)]
pub struct LlmpBrokerSignalHandler {
    shutting_down: bool,
}

#[cfg(all(unix))]
impl Handler for LlmpBrokerSignalHandler {
    fn handle(&mut self, _signal: Signal, _info: siginfo_t, _void: c_void) {
        unsafe { ptr::write_volatile(&mut self.shutting_down, true) };
    }

    fn signals(&self) -> Vec<Signal> {
        vec![Signal::SigTerm, Signal::SigInterrupt, Signal::SigQuit]
    }
}

/// The broker forwards all messages to its own bus-like broadcast map.
/// It may intercept messages passing through.
impl<SH> LlmpBroker<SH>
where
    SH: ShMem,
{
    /// Create and initialize a new llmp_broker
    pub fn new() -> Result<Self, Error> {
        let broker = LlmpBroker {
            llmp_out: LlmpSender {
                id: 0,
                last_msg_sent: ptr::null_mut(),
                out_maps: vec![LlmpSharedMap::new(0, SH::new_map(new_map_size(0))?)],
                // Broker never cleans up the pages so that new
                // clients may join at any time
                keep_pages_forever: true,
            },
            llmp_clients: vec![],
            socket_name: None,
            shutting_down: false,
        };

        Ok(broker)
    }

    /// Allocate the next message on the outgoing map
    unsafe fn alloc_next(&mut self, buf_len: usize) -> Result<*mut LlmpMsg, Error> {
        self.llmp_out.alloc_next(buf_len)
    }

    /// Registers a new client for the given sharedmap str and size.
    /// Returns the id of the new client in broker.client_map
    pub fn register_client(&mut self, mut client_page: LlmpSharedMap<SH>) {
        // Tell the client it may unmap this page now.
        client_page.mark_save_to_unmap();

        let id = self.llmp_clients.len() as u32;
        self.llmp_clients.push(LlmpReceiver {
            id,
            current_recv_map: client_page,
            last_msg_recvd: ptr::null_mut(),
        });
    }

    /// For internal use: Forward the current message to the out map.
    unsafe fn forward_msg(&mut self, msg: *mut LlmpMsg) -> Result<(), Error> {
        let mut out: *mut LlmpMsg = self.alloc_next((*msg).buf_len_padded as usize)?;

        /* Copy over the whole message.
        If we should need zero copy, we could instead post a link to the
        original msg with the map_id and offset. */
        let actual_size = (*out).buf_len_padded;
        msg.copy_to_nonoverlapping(out, size_of::<LlmpMsg>() + (*msg).buf_len_padded as usize);
        (*out).buf_len_padded = actual_size;
        /* We need to replace the message ID with our own */
        if let Err(e) = self.llmp_out.send(out) {
            panic!("Error sending msg: {:?}", e)
        };
        self.llmp_out.last_msg_sent = out;
        Ok(())
    }

    /// The broker walks all pages and looks for changes, then broadcasts them on
    /// its own shared page, once.
    #[inline]
    pub fn once<F>(&mut self, on_new_msg: &mut F) -> Result<(), Error>
    where
        F: FnMut(u32, Tag, &[u8]) -> Result<LlmpMsgHookResult, Error>,
    {
        compiler_fence(Ordering::SeqCst);
        for i in 0..self.llmp_clients.len() {
            unsafe {
                self.handle_new_msgs(i as u32, on_new_msg)?;
            }
        }
        Ok(())
    }

    /// Internal function, returns true when shuttdown is requested by a `SIGINT` signal
    #[inline]
    #[cfg(unix)]
    fn is_shutting_down(&self) -> bool {
        unsafe { ptr::read_volatile(&GLOBAL_SIGHANDLER_STATE.shutting_down) }
    }

    /// Always returns true on platforms, where no shutdown signal handlers are supported
    #[inline]
    #[cfg(not(unix))]
    fn is_shutting_down(&self) -> bool {
        false
    }

    /// Loops infinitely, forwarding and handling all incoming messages from clients.
    /// Never returns. Panics on error.
    /// 5 millis of sleep can't hurt to keep busywait not at 100%
    pub fn loop_forever<F>(&mut self, on_new_msg: &mut F, sleep_time: Option<Duration>)
    where
        F: FnMut(u32, Tag, &[u8]) -> Result<LlmpMsgHookResult, Error>,
    {
        #[cfg(unix)]
        if let Err(_e) = unsafe { setup_signal_handler(&mut GLOBAL_SIGHANDLER_STATE) } {
            // We can live without a proper ctrl+c signal handler. Print and ignore.
            #[cfg(feature = "std")]
            println!("Failed to setup signal handlers: {}", _e);
        }

        while !self.is_shutting_down() {
            compiler_fence(Ordering::SeqCst);
            self.once(on_new_msg)
                .expect("An error occurred when brokering. Exiting.");

            #[cfg(feature = "std")]
            if let Some(time) = sleep_time {
                thread::sleep(time)
            };

            #[cfg(not(feature = "std"))]
            match sleep_time {
                Some(_) => {
                    panic!("Cannot sleep on no_std platform");
                }
                None => (),
            }
        }
        self.llmp_out
            .send_buf(LLMP_TAG_EXITING, &[])
            .expect("Error when shutting down broker: Could not send LLMP_TAG_EXITING msg.");
    }

    /// Broadcasts the given buf to all lients
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        self.llmp_out.send_buf(tag, buf)
    }

    #[cfg(feature = "std")]
    /// Launches a thread using a tcp listener socket, on which new clients may connect to this broker
    /// Does so on the given port.
    pub fn launch_tcp_listener_on(&mut self, port: u16) -> Result<thread::JoinHandle<()>, Error> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
        // accept connections and process them, spawning a new thread for each one
        println!("Server listening on port {}", port);
        self.launch_listener(Listener::Tcp(listener))
    }

    #[cfg(feature = "std")]
    /// Launches a thread using a listener socket, on which new clients may connect to this broker
    pub fn launch_listener(&mut self, listener: Listener) -> Result<thread::JoinHandle<()>, Error> {
        // Later in the execution, after the initial map filled up,
        // the current broacast map will will point to a different map.
        // However, the original map is (as of now) never freed, new clients will start
        // to read from the initial map id.

        let client_out_map_mem = &self.llmp_out.out_maps.first().unwrap().shmem;
        let broadcast_map_description = postcard::to_allocvec(&client_out_map_mem.description())?;
        let client_out_map_mem_fd: i32 = client_out_map_mem.shm_str().parse().unwrap();

        let mut incoming_map_description_serialized = vec![0u8; broadcast_map_description.len()];

        let llmp_tcp_id = self.llmp_clients.len() as u32;

        // Tcp out map sends messages from background thread tcp server to foreground client
        let tcp_out_map = LlmpSharedMap::new(
            llmp_tcp_id,
            SH::new_map(new_map_size(LLMP_CFG_INITIAL_MAP_SIZE))?,
        );
        let tcp_out_map_str = tcp_out_map.shmem.shm_str();
        let tcp_out_map_size = tcp_out_map.shmem.map().len();
        self.register_client(tcp_out_map);

        Ok(thread::spawn(move || {
            let mut new_client_sender = LlmpSender {
                id: 0,
                last_msg_sent: ptr::null_mut(),
                out_maps: vec![LlmpSharedMap::existing(
                    SH::existing_from_shm_str(&tcp_out_map_str, tcp_out_map_size).unwrap(),
                )],
                // drop pages to the broker if it already read them
                keep_pages_forever: false,
            };

            loop {
                match listener.accept() {
                    ListenerStream::Tcp(mut stream, addr) => {
                        dbg!("New connection", addr, stream.peer_addr().unwrap());
                        match stream.write(&broadcast_map_description) {
                            Ok(_) => {} // fire & forget
                            Err(e) => {
                                dbg!("Could not send to shmap to client", e);
                                continue;
                            }
                        };
                        match stream.read_exact(&mut incoming_map_description_serialized) {
                            Ok(()) => (),
                            Err(e) => {
                                dbg!("Ignoring failed read from client", e);
                                continue;
                            }
                        };
                        if let Ok(incoming_map_description) = postcard::from_bytes::<ShMemDescription>(
                            &incoming_map_description_serialized,
                        ) {
                            unsafe {
                                let msg = new_client_sender
                                    .alloc_next(size_of::<LlmpPayloadSharedMapInfo>())
                                    .expect("Could not allocate a new message in shared map.");
                                (*msg).tag = LLMP_TAG_NEW_SHM_CLIENT;
                                let pageinfo =
                                    (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;
                                (*pageinfo).shm_str = incoming_map_description.str_bytes;
                                (*pageinfo).map_size = incoming_map_description.size;
                                match new_client_sender.send(msg) {
                                    Ok(()) => (),
                                    Err(e) => println!("Error forwarding client on map: {:?}", e),
                                };
                            }
                        }
                    }
                    #[cfg(unix)]
                    ListenerStream::Unix(stream, addr) => unsafe {
                        dbg!("New connection", addr);

                        let broadcast_fd_initial: i32 = client_out_map_mem_fd;

                        match sendmsg(
                            stream.as_raw_fd(),
                            &[IoVec::from_slice(b"\x00")],
                            &[ControlMessage::ScmRights(&[broadcast_fd_initial])],
                            MsgFlags::empty(),
                            None,
                        ) {
                            Ok(_) => {}
                            Err(err) => {
                                dbg!("Error sending fd over stream: {}", err);
                                continue;
                            }
                        };

                        let mut buf = [0u8; 5];
                        let mut cmsgspace = cmsg_space!([RawFd; 1]);
                        let msg = recvmsg(
                            stream.as_raw_fd(),
                            &[IoVec::from_mut_slice(&mut buf[..])],
                            Some(&mut cmsgspace),
                            MsgFlags::empty(),
                        )
                        .unwrap();

                        for cmsg in msg.cmsgs() {
                            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                                for fd in fds {
                                    let mut fdstr = [0u8; 20];
                                    match write!(&mut fdstr[..], "{}", fd) {
                                        Ok(_) => {}
                                        Err(_) => {
                                            dbg!("error converting fd to string");
                                        }
                                    }

                                    let msg = new_client_sender
                                        .alloc_next(size_of::<LlmpPayloadSharedMapInfo>())
                                        .expect("Could not allocate a new message in shared map.");
                                    (*msg).tag = LLMP_TAG_NEW_SHM_CLIENT;
                                    let pageinfo =
                                        (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;
                                    (*pageinfo).shm_str = fdstr;
                                    (*pageinfo).map_size = LLMP_CFG_INITIAL_MAP_SIZE;
                                    match new_client_sender.send(msg) {
                                        Ok(()) => (),
                                        Err(e) => {
                                            println!("Error forwarding client on map: {:?}", e)
                                        }
                                    };
                                }
                            }
                        }
                    },
                    ListenerStream::Empty() => {
                        continue;
                    }
                };
            }
        }))
    }

    /// broker broadcast to its own page for all others to read */
    #[inline]
    unsafe fn handle_new_msgs<F>(&mut self, client_id: u32, on_new_msg: &mut F) -> Result<(), Error>
    where
        F: FnMut(u32, Tag, &[u8]) -> Result<LlmpMsgHookResult, Error>,
    {
        let mut next_id = self.llmp_clients.len() as u32;

        // TODO: We could memcpy a range of pending messages, instead of one by one.
        loop {
            let msg = {
                let client = &mut self.llmp_clients[client_id as usize];
                match client.recv()? {
                    None => {
                        // We're done handling this client
                        return Ok(());
                    }
                    Some(msg) => msg,
                }
            };

            if (*msg).tag == LLMP_TAG_NEW_SHM_CLIENT {
                /* This client informs us about yet another new client
                add it to the list! Also, no need to forward this msg. */
                if (*msg).buf_len < size_of::<LlmpPayloadSharedMapInfo>() as u64 {
                    #[cfg(feature = "std")]
                    println!("Ignoring broken CLIENT_ADDED msg due to incorrect size. Expected {} but got {}",
                        (*msg).buf_len_padded,
                        size_of::<LlmpPayloadSharedMapInfo>()
                    );
                    #[cfg(not(feature = "std"))]
                    return Err(Error::Unknown(format!("Broken CLIENT_ADDED msg with incorrect size received. Expected {} but got {}",
                       (*msg).buf_len_padded,
                        size_of::<LlmpPayloadSharedMapInfo>()
                    )));
                } else {
                    let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;

                    match SH::existing_from_shm_slice(&(*pageinfo).shm_str, (*pageinfo).map_size) {
                        Ok(new_map) => {
                            let mut new_page = LlmpSharedMap::existing(new_map);
                            let id = next_id;
                            next_id += 1;
                            new_page.mark_save_to_unmap();
                            self.llmp_clients.push(LlmpReceiver {
                                id,
                                current_recv_map: new_page,
                                last_msg_recvd: ptr::null_mut(),
                            });
                        }
                        Err(e) => {
                            #[cfg(feature = "std")]
                            println!("Error adding client! Ignoring: {:?}", e);
                            #[cfg(not(feature = "std"))]
                            return Err(Error::Unknown(format!(
                                "Error adding client! PANIC! {:?}",
                                e
                            )));
                        }
                    };
                }
            } else {
                // The message is not specifically for use. Let the user handle it, then forward it to the clients, if necessary.
                let mut should_forward_msg = true;

                let map = &mut self.llmp_clients[client_id as usize].current_recv_map;
                let msg_buf = (*msg).as_slice(map)?;
                if let LlmpMsgHookResult::Handled = (on_new_msg)(client_id, (*msg).tag, msg_buf)? {
                    should_forward_msg = false
                };
                if should_forward_msg {
                    self.forward_msg(msg)?;
                }
            }
        }
    }
}

#[cfg(feature = "std")]
impl<SH> Drop for LlmpBroker<SH>
where
    SH: ShMem,
{
    fn drop(&mut self) {
        match &self.socket_name {
            Some(name) => match fs::remove_file(&name) {
                Ok(_) => {}
                Err(err) => {
                    dbg!("failed to close socket: {}", err);
                }
            },
            None => {}
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
#[derive(Clone, Debug)]
pub struct LlmpClient<SH>
where
    SH: ShMem,
{
    /// Outgoing channel to the broker
    pub sender: LlmpSender<SH>,
    /// Incoming (broker) broadcast map
    pub receiver: LlmpReceiver<SH>,
}

/// `n` clients connect to a broker. They share an outgoing map with the broker,
/// and get incoming messages from the shared broker bus
impl<SH> LlmpClient<SH>
where
    SH: ShMem,
{
    /// Reattach to a vacant client map.
    /// It is essential, that the broker (or someone else) kept a pointer to the out_map
    /// else reattach will get a new, empty page, from the OS, or fail
    pub fn on_existing_map(
        current_out_map: SH,
        last_msg_sent_offset: Option<u64>,
        current_broker_map: SH,
        last_msg_recvd_offset: Option<u64>,
    ) -> Result<Self, Error> {
        Ok(Self {
            receiver: LlmpReceiver::on_existing_map(current_broker_map, last_msg_recvd_offset)?,
            sender: LlmpSender::on_existing_map(current_out_map, last_msg_sent_offset)?,
        })
    }

    /// Recreate this client from a previous client.to_env
    #[cfg(feature = "std")]
    pub fn on_existing_from_env(env_name: &str) -> Result<Self, Error> {
        Ok(Self {
            sender: LlmpSender::on_existing_from_env(&format!("{}_SENDER", env_name))?,
            receiver: LlmpReceiver::on_existing_from_env(&format!("{}_RECEIVER", env_name))?,
        })
    }

    /// Write the current state to env.
    /// A new client can attach to exactly the same state by calling on_existing_map.
    #[cfg(feature = "std")]
    pub fn to_env(&self, env_name: &str) -> Result<(), Error> {
        self.sender.to_env(&format!("{}_SENDER", env_name))?;
        self.receiver.to_env(&format!("{}_RECEIVER", env_name))
    }

    /// Describe this client in a way that it can be recreated, for example after crash
    fn describe(&self) -> Result<LlmpClientDescription, Error> {
        Ok(LlmpClientDescription {
            sender: self.sender.describe()?,
            receiver: self.receiver.describe()?,
        })
    }

    /// Create an existing client from description
    fn existing_client_from_description(
        description: &LlmpClientDescription,
    ) -> Result<Self, Error> {
        Ok(Self {
            sender: LlmpSender::on_existing_from_description(&description.sender)?,
            receiver: LlmpReceiver::on_existing_from_description(&description.receiver)?,
        })
    }

    /// Waits for the sender to be save to unmap.
    /// If a receiver is involved on the other side, this function should always be called.
    pub fn await_save_to_unmap_blocking(&self) {
        self.sender.await_save_to_unmap_blocking();
    }

    /// If we are allowed to unmap this client
    pub fn save_to_unmap(&self) -> bool {
        self.sender.save_to_unmap()
    }

    /// Creates a new LlmpClient
    pub fn new(initial_broker_map: LlmpSharedMap<SH>) -> Result<Self, Error> {
        Ok(Self {
            sender: LlmpSender {
                id: 0,
                last_msg_sent: ptr::null_mut(),
                out_maps: vec![LlmpSharedMap::new(
                    0,
                    SH::new_map(new_map_size(LLMP_CFG_INITIAL_MAP_SIZE))?,
                )],
                // drop pages to the broker if it already read them
                keep_pages_forever: false,
            },

            receiver: LlmpReceiver {
                id: 0,
                current_recv_map: initial_broker_map,
                last_msg_recvd: ptr::null_mut(),
            },
        })
    }

    /// Commits a msg to the client's out map
    /// # Safety
    /// Needs to be called with a proper msg pointer
    pub unsafe fn send(&mut self, msg: *mut LlmpMsg) -> Result<(), Error> {
        self.sender.send(msg)
    }

    /// Allocates a message of the given size, tags it, and sends it off.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), Error> {
        self.sender.send_buf(tag, buf)
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

    /// The current page could have changed in recv (EOP)
    /// Alloc the next message, internally handling end of page by allocating a new one.
    /// # Safety
    /// Should be safe, but returns an unsafe ptr
    #[inline]
    pub unsafe fn alloc_next(&mut self, buf_len: usize) -> Result<*mut LlmpMsg, Error> {
        self.sender.alloc_next(buf_len)
    }

    /// Returns the next message, tag, buf, if avaliable, else None
    #[inline]
    pub fn recv_buf(&mut self) -> Result<Option<(u32, u32, &[u8])>, Error> {
        self.receiver.recv_buf()
    }

    /// Receives a buf from the broker, looping until a messages becomes avaliable
    #[inline]
    pub fn recv_buf_blocking(&mut self) -> Result<(u32, u32, &[u8]), Error> {
        self.receiver.recv_buf_blocking()
    }

    #[cfg(feature = "std")]
    /// Creates a new LlmpClient, reading the map id and len from env
    pub fn create_using_env(env_var: &str) -> Result<Self, Error> {
        Self::new(LlmpSharedMap::existing(SH::existing_from_env(env_var)?))
    }

    #[cfg(feature = "std")]
    /// Create a LlmpClient, getting the ID from a given port
    pub fn create_attach_to_tcp(port: u16) -> Result<Self, Error> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
        println!("Connected to port {}", port);

        // First, get the serialized description size by serializing a dummy.
        let dummy_description = ShMemDescription {
            size: 0,
            str_bytes: Default::default(),
        };
        let mut new_broker_map_str = postcard::to_allocvec(&dummy_description)?;

        stream.read_exact(&mut new_broker_map_str)?;

        let broker_map_description: ShMemDescription = postcard::from_bytes(&new_broker_map_str)?;

        let ret = Self::new(LlmpSharedMap::existing(SH::existing_from_description(
            &broker_map_description,
        )?))?;

        let own_map_description_bytes =
            postcard::to_allocvec(&ret.sender.out_maps.first().unwrap().shmem.description())?;
        stream.write_all(&own_map_description_bytes)?;
        Ok(ret)
    }
}

/// `n` clients connect to a broker. They share an outgoing map with the broker,
/// and get incoming messages from the shared broker bus
/// If the Shm has a fd, we can attach to it.
#[cfg(all(unix, feature = "std"))]
impl<SH> LlmpClient<SH>
where
    SH: ShMem,
{
    #[cfg(all(unix, feature = "std"))]
    /// Create a LlmpClient, getting the ID from a given filename
    pub fn create_attach_to_unix(filename: &str) -> Result<Self, Error> {
        let stream = UnixStream::connect_to_unix_addr(&UnixSocketAddr::new(filename).unwrap())?;
        println!("Connected to socket {}", filename);

        let mut buf = [0u8; 5];
        let mut cmsgspace = cmsg_space!([RawFd; 1]);
        let msg = recvmsg(
            stream.as_raw_fd(),
            &[IoVec::from_mut_slice(&mut buf[..])],
            Some(&mut cmsgspace),
            MsgFlags::empty(),
        )
        .unwrap();

        for cmsg in msg.cmsgs() {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                for fd in fds {
                    let mut fdstr = [0u8; 20];
                    match write!(&mut fdstr[..], "{}", fd) {
                        Ok(_) => {}
                        Err(_) => {
                            dbg!("error converting fd to string");
                        }
                    }

                    let ret = Self::new(LlmpSharedMap::existing(SH::existing_from_shm_slice(
                        &fdstr,
                        LLMP_CFG_INITIAL_MAP_SIZE,
                    )?))?;

                    match sendmsg(
                        stream.as_raw_fd(),
                        &[IoVec::from_slice(b"\x00")],
                        &[ControlMessage::ScmRights(&[ret
                            .sender
                            .out_maps
                            .first()
                            .unwrap()
                            .shmem
                            .shm_str().parse().unwrap()])],
                        MsgFlags::empty(),
                        None,
                    ) {
                        Ok(_) => {}
                        Err(err) => {
                            dbg!("Error sending fd over stream {}", err);
                            continue;
                        }
                    };
                    return Ok(ret);
                }
            }
        }

        panic!("Didn't receive a file descriptor from the broker!");
    }
}

#[cfg(test)]
#[cfg(all(unix, feature = "std"))]
mod tests {

    use std::{thread::sleep, time::Duration};

    use super::{
        LlmpClient,
        LlmpConnection::{self, IsBroker, IsClient},
        LlmpMsgHookResult::ForwardToClients,
        Tag,
    };

    use crate::bolts::shmem::UnixShMem;

    #[test]
    pub fn llmp_connection() {
        let mut broker = match LlmpConnection::<UnixShMem>::on_port(1337).unwrap() {
            IsClient { client: _ } => panic!("Could not bind to port as broker"),
            IsBroker { broker } => broker,
        };

        // Add the first client (2nd, actually, because of the tcp listener client)
        let mut client = match LlmpConnection::<UnixShMem>::on_port(1337).unwrap() {
            IsBroker { broker: _ } => panic!("Second connect should be a client!"),
            IsClient { client } => client,
        };

        // Give the (background) tcp thread a few millis to post the message
        sleep(Duration::from_millis(100));
        broker
            .once(&mut |_sender_id, _tag, _msg| Ok(ForwardToClients))
            .unwrap();

        let tag: Tag = 0x1337;
        let arr: [u8; 1] = [1u8];
        // Send stuff
        client.send_buf(tag, &arr).unwrap();

        client.to_env("_ENV_TEST").unwrap();
        dbg!(std::env::vars());

        for (key, value) in std::env::vars_os() {
            println!("{:?}: {:?}", key, value);
        }

        /* recreate the client from env, check if it still works */
        client = LlmpClient::<UnixShMem>::on_existing_from_env("_ENV_TEST").unwrap();

        client.send_buf(tag, &arr).unwrap();

        // Forward stuff to clients
        broker
            .once(&mut |_sender_id, _tag, _msg| Ok(ForwardToClients))
            .unwrap();
        let (_sender_id, tag2, arr2) = client.recv_buf_blocking().unwrap();
        assert_eq!(tag, tag2);
        assert_eq!(arr[0], arr2[0]);

        // We want at least the tcp and sender clients.
        assert_eq!(broker.llmp_clients.len(), 2);
    }
}
