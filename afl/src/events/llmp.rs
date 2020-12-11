/*!
A PoC for low level message passing

To send new messages, the clients place a new message at the end of their
client_out_map. If the ringbuf is filled up, they start place a
LLMP_AGE_END_OF_PAGE_V1 msg and alloc a new shmap.
Once the broker mapped a page, it flags it save for unmapping.

[client0]        [client1]    ...    [clientN]
  |                  |                 /
[client0_out] [client1_out] ... [clientN_out]
  |                 /                /
  |________________/                /
  |________________________________/
 \|/
[broker]

After the broker received a new message for clientN, (clientN_out->current_id
!= last_message->message_id) the broker will copy the message content to its
own, centralized page.

The clients periodically check (current_broadcast_map->current_id !=
last_message->message_id) for new incoming messages. If the page is filled up,
the broker instead creates a new page and places a LLMP_TAG_END_OF_PAGE_V1
message in its queue. The LLMP_TAG_END_PAGE_V1 buf contains the new string to
access the shared map. The clients then switch over to read from that new
current map.

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

In the future, if we need zero copy, the current_broadcast_map could instead
list the client_out_map ID an offset for each message. In that case, the clients
also need to create new shmaps once their bufs are filled up.


To use, you will have to create a broker using llmp_broker_new().
Then register some clientloops using llmp_broker_register_threaded_clientloop
(or launch them as seperate processes) and call llmp_broker_run();

*/

use core::{
    cmp::max,
    mem::size_of,
    ptr, slice,
    sync::atomic::{compiler_fence, Ordering},
    time::Duration,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
};

use crate::utils::next_pow2;
use crate::AflError;

use super::shmem_translated::AflShmem;

/// We'll start off with 256 megabyte maps per fuzzer client
const LLMP_PREF_INITIAL_MAP_SIZE: usize = 1 << 28;
/// What byte count to align messages to
/// LlmpMsg sizes (including header) will always be rounded up to be a multiple of this value
const LLMP_PREF_ALIGNNMENT: usize = 64;

/// A msg fresh from the press: No tag got sent by the user yet
const LLMP_TAG_UNSET: u32 = 0xDEADAF;
/// This message should not exist yet. Some bug in unsafe code!
const LLMP_TAG_UNINITIALIZED: u32 = 0xA143AF11;
/// The end of page mesasge
/// When receiving this, a new sharedmap needs to be allocated.
const LLMP_TAG_END_OF_PAGE: u32 = 0xAF1E0F1;
/// A new client for this broekr got added.
const LLMP_TAG_NEW_SHM_CLIENT: u32 = 0xC11E471;

/// Size of a new page message, header, payload, and alignment
const EOP_MSG_SIZE: usize =
    llmp_align(size_of::<LlmpMsg>() + size_of::<LlmpPayloadSharedMapInfo>());
/// The header length of a llmp page in a shared map (until messages start)
const LLMP_PAGE_HEADER_LEN: usize = size_of::<LlmpPage>();

/// Message hook type
pub type LlmpMsgHookFn = unsafe fn(client_id: u32, msg: *mut LlmpMsg) -> LlmpMsgHookResult;

/// TAGs used thorughout llmp
pub type Tag = u32;

/// Sending end on a (unidirectional) sharedmap channel
#[derive(Clone)]
pub struct LlmpSender {
    /// ID of this sender. Only used in the broker.
    pub id: u32,
    /// Ref to the last message this sender sent on the last page.
    /// If null, a new page (just) started.
    pub last_msg_sent: *mut LlmpMsg,
    /// A vec of page wrappers, each containing an intialized AfShmem
    pub out_maps: Vec<LlmpSharedMap>,
    /// If true, pages will never be pruned.
    /// The broker uses this feature.
    /// By keeping the message history around,
    /// new clients may join at any time in the future.
    pub keep_pages_forever: bool,
}

/// Receiving end on a (unidirectional) sharedmap channel
#[derive(Clone)]
pub struct LlmpReceiver {
    pub id: u32,
    /// Pointer to the last meg this received
    pub last_msg_recvd: *mut LlmpMsg,
    /// current page. After EOP, this gets replaced with the new one
    pub current_recv_map: LlmpSharedMap,
}

/// Client side of LLMP
#[derive(Clone)]
pub struct LlmpClient {
    /// Outgoing channel to the broker
    pub llmp_out: LlmpSender,
    /// Incoming (broker) broadcast map
    pub llmp_in: LlmpReceiver,
}

/// A page wrapper
#[derive(Clone)]
pub struct LlmpSharedMap {
    /// Shmem containg the actual (unsafe) page,
    /// shared between one LlmpSender and one LlmpReceiver
    shmem: AflShmem,
}
/// Message sent over the "wire"
#[derive(Copy, Clone)]
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
    /// This is unsafe if somebody has access to shared mem pages on the system.
    pub unsafe fn as_slice_unsafe(&self) -> &[u8] {
        slice::from_raw_parts(self.buf.as_ptr(), self.buf_len as usize)
    }

    /// Gets the buffer from this message as slice, with the corrent length.
    #[inline]
    pub fn as_slice(&self, map: &LlmpSharedMap) -> Result<&[u8], AflError> {
        unsafe {
            if self.in_map(map) {
                Ok(self.as_slice_unsafe())
            } else {
                Err(AflError::IllegalState("Current message not in page. The sharedmap get tampered with or we have a BUG.".into()))
            }
        }
    }

    /// Returns true, if the pointer is, indeed, in the page of this shared map.
    #[inline]
    pub fn in_map(&self, map: &LlmpSharedMap) -> bool {
        unsafe {
            let buf_ptr = self.buf.as_ptr();
            if buf_ptr > (map.page() as *const u8).offset(size_of::<LlmpPage>() as isize)
                && buf_ptr
                    <= (map.page() as *const u8)
                        .offset((map.shmem.map_size - size_of::<LlmpMsg>() as usize) as isize)
            {
                // The message header is in the page. Continue with checking the body.
                let len = self.buf_len_padded as usize + size_of::<LlmpMsg>();
                buf_ptr <= (map.page() as *const u8).offset((map.shmem.map_size - len) as isize)
            } else {
                false
            }
        }
    }
}

/// An Llmp instance
pub enum LlmpConnection {
    /// A broker and a thread using this tcp background thread
    IsBroker {
        broker: LlmpBroker,
        listener_thread: thread::JoinHandle<()>,
    },
    /// A client, connected to the port
    IsClient { client: LlmpClient },
}

impl LlmpConnection {
    /// Creates either a broker, if the tcp port is not bound, or a client, connected to this port.
    pub fn on_port(port: u16) -> Result<Self, AflError> {
        match TcpListener::bind(format!("127.0.0.1:{}", port)) {
            Ok(listener) => {
                // We got the port. We are the broker! :)
                dbg!("We're the broker");
                let mut broker = LlmpBroker::new()?;
                let listener_thread = broker.launch_tcp_listener(listener)?;
                Ok(LlmpConnection::IsBroker {
                    broker,
                    listener_thread,
                })
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
                    _ => Err(AflError::File(e)),
                }
            }
        }
    }
}

/// Contents of the share mem pages, used by llmp internally
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct LlmpPage {
    pub sender: u32,
    pub save_to_unmap: u16,
    pub sender_dead: u16,
    pub current_msg_id: u64,
    pub size_total: usize,
    pub size_used: usize,
    pub max_alloc_size: usize,
    pub messages: [LlmpMsg; 0],
}

/// The broker (node 0)
#[derive(Clone)]
#[repr(C)]
pub struct LlmpBroker {
    /// Broadcast map from broker to all clients
    pub llmp_out: LlmpSender,
    /// Users of Llmp can add message handlers in the broker.
    /// This allows us to intercept messages right in the broker
    /// This keeps the out map clean.
    pub msg_hooks: Vec<LlmpMsgHookFn>,
    pub llmp_clients: Vec<LlmpReceiver>,
}

/// Result of an LLMP Mesasge hook
pub enum LlmpMsgHookResult {
    /// This has been handled in the broker. No need to forward.
    Handled,
    /// Forward this to the clients. We are not done here.
    ForwardToClients,
}

/// Message payload when a client got added LLMP_TAG_CLIENT_ADDED_V1 */
/// This is an internal message!
/// LLMP_TAG_END_OF_PAGE_V1
#[derive(Copy, Clone)]
#[repr(C, packed)]
struct LlmpPayloadSharedMapInfo {
    pub map_size: usize,
    pub shm_str: [u8; 20],
}

/// Get sharedmem from a page
#[inline]
unsafe fn shmem2page(afl_shmem: &AflShmem) -> *mut LlmpPage {
    afl_shmem.map as *mut LlmpPage
}

/// Return, if a msg is contained in the current page
#[inline]
unsafe fn llmp_msg_in_page(page: *mut LlmpPage, msg: *mut LlmpMsg) -> bool {
    /* DBG("llmp_msg_in_page %p within %p-%p\n", msg, page, page + page->size_total); */
    return (page as *mut u8) < msg as *mut u8
        && (page as *mut u8).offset((*page).size_total as isize) > msg as *mut u8;
}

/// allign to LLMP_PREF_ALIGNNMENT=64 bytes
#[inline]
const fn llmp_align(to_align: usize) -> usize {
    // check if we need to align first
    if LLMP_PREF_ALIGNNMENT == 0 {
        return to_align;
    }
    // Then do the alignment
    let modulo = to_align % LLMP_PREF_ALIGNNMENT;
    if modulo == 0 {
        to_align
    } else {
        to_align + LLMP_PREF_ALIGNNMENT - modulo
    }
}

/// In case we don't have enough space, make sure the next page will be large
/// enough. For now, we want to have at least enough space to store 2 of the
/// largest messages we encountered (plus message one new_page message).
#[inline]
fn new_map_size(max_alloc: usize) -> usize {
    next_pow2(max(
        max_alloc * 2 + EOP_MSG_SIZE + LLMP_PAGE_HEADER_LEN,
        LLMP_PREF_INITIAL_MAP_SIZE,
    ) as u64) as usize
}

/// Initialize a new llmp_page. size should be relative to
/// llmp_page->messages
unsafe fn _llmp_page_init(shmem: &mut AflShmem, sender: u32) {
    let page = shmem2page(&shmem);
    (*page).sender = sender;
    ptr::write_volatile(&mut (*page).current_msg_id, 0);
    (*page).max_alloc_size = 0;
    // Don't forget to subtract our own header size
    (*page).size_total = shmem.map_size - LLMP_PAGE_HEADER_LEN;
    (*page).size_used = 0;
    (*(*page).messages.as_mut_ptr()).message_id = 0;
    (*(*page).messages.as_mut_ptr()).tag = LLMP_TAG_UNSET;
    ptr::write_volatile(&mut (*page).save_to_unmap, 0);
    ptr::write_volatile(&mut (*page).sender_dead, 0);
}

/// Get the next pointer and make sure it's in the current page, and has enough space.
#[inline]
unsafe fn llmp_next_msg_ptr_checked(
    map: &LlmpSharedMap,
    last_msg: *const LlmpMsg,
    alloc_size: usize,
) -> Result<*mut LlmpMsg, AflError> {
    let page = map.page();
    let msg_begin_min = (page as *const u8).offset(size_of::<LlmpPage>() as isize);
    // We still need space for this msg (alloc_size).
    let msg_begin_max = (page as *const u8).offset((map.shmem.map_size - alloc_size) as isize);
    let next = _llmp_next_msg_ptr(last_msg);
    let next_ptr = next as *const u8;
    if next_ptr >= msg_begin_min && next_ptr <= msg_begin_max {
        Ok(next)
    } else {
        Err(AflError::IllegalState(format!(
            "Inconsistent data on sharedmap, or Bug (next_ptr was {:x}, sharedmap page was {:x})",
            next_ptr as usize, page as usize
        )))
    }
}

/// Pointer to the message behind the last message
#[inline]
unsafe fn _llmp_next_msg_ptr(last_msg: *const LlmpMsg) -> *mut LlmpMsg {
    /* DBG("_llmp_next_msg_ptr %p %lu + %lu\n", last_msg, last_msg->buf_len_padded, sizeof(llmp_message)); */
    return (last_msg as *mut u8)
        .offset(size_of::<LlmpMsg>() as isize)
        .offset((*last_msg).buf_len_padded as isize) as *mut LlmpMsg;
}

/// An actor on the sendin part of the shared map
impl LlmpSender {
    /// For non zero-copy, we want to get rid of old pages with duplicate messages in the client
    /// eventually. This function This funtion sees if we can unallocate older pages.
    /// The broker would have informed us by setting the save_to_unmap-flag.
    unsafe fn prune_old_pages(&mut self) {
        // Exclude the current page by splitting of the last element for this iter
        let mut unmap_until_excl = 0;
        for map in self.out_maps.split_last().unwrap().1 {
            if (*map.page()).save_to_unmap == 0 {
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
    unsafe fn alloc_eop(&mut self) -> Result<*mut LlmpMsg, AflError> {
        let map = self.out_maps.last().unwrap();
        let page = map.page();
        let last_msg = self.last_msg_sent;
        if (*page).size_used + EOP_MSG_SIZE > (*page).size_total {
            panic!(format!("PROGRAM ABORT : BUG: EOP does not fit in page! page {:?}, size_current {:?}, size_total {:?}", page,
                (*page).size_used, (*page).size_total));
        }
        let mut ret: *mut LlmpMsg = if !last_msg.is_null() {
            llmp_next_msg_ptr_checked(&map, last_msg, EOP_MSG_SIZE)?
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
        let mut buf_len_padded = buf_len;
        let mut complete_msg_size = llmp_align(size_of::<LlmpMsg>() + buf_len_padded);
        let map = self.out_maps.last().unwrap();
        let page = map.page();
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
            panic!(format!("BUG: The current message never got commited using send! (page->current_msg_id {:?}, last_msg->message_id: {})", (*page).current_msg_id, (*last_msg).message_id));
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
                    dbg!("Unexpected error allocing new msg", e);
                    return None;
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
            panic!(format!("Allocated new message without calling send() inbetween. ret: {:?}, page: {:?}, complete_msg_size: {:?}, size_used: {:?}, last_msg: {:?}", ret, page,
                buf_len_padded, (*page).size_used, last_msg));
        }
        (*page).size_used = (*page).size_used + complete_msg_size;
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
    unsafe fn send(&mut self, msg: *mut LlmpMsg) -> Result<(), AflError> {
        if self.last_msg_sent == msg {
            panic!("Message sent twice!");
        }
        if (*msg).tag == LLMP_TAG_UNSET {
            panic!(format!(
                "No tag set on message with id {}",
                (*msg).message_id
            ));
        }
        let page = self.out_maps.last().unwrap().page();
        if msg.is_null() || !llmp_msg_in_page(page, msg) {
            return Err(AflError::Unknown(format!(
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
    unsafe fn handle_out_eop(&mut self) -> Result<(), AflError> {
        let old_map = self.out_maps.last_mut().unwrap().page();

        // Create a new shard page.
        let new_map_shmem = LlmpSharedMap::new((*old_map).sender, (*old_map).max_alloc_size)?;
        let mut new_map = new_map_shmem.page();

        ptr::write_volatile(&mut (*new_map).current_msg_id, (*old_map).current_msg_id);
        (*new_map).max_alloc_size = (*old_map).max_alloc_size;
        /* On the old map, place a last message linking to the new map for the clients
         * to consume */
        let mut out: *mut LlmpMsg = self.alloc_eop()?;
        (*out).sender = (*old_map).sender;

        let mut end_of_page_msg = (*out).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;
        (*end_of_page_msg).map_size = new_map_shmem.shmem.map_size;
        (*end_of_page_msg).shm_str = new_map_shmem.shmem.shm_str;

        // We never sent a msg on the new buf */
        self.last_msg_sent = 0 as *mut LlmpMsg;

        /* Send the last msg on the old buf */
        self.send(out)?;

        if !self.keep_pages_forever {
            self.prune_old_pages();
        }

        self.out_maps.push(new_map_shmem);

        Ok(())
    }

    /// Allocates the next space on this sender page
    pub unsafe fn alloc_next(&mut self, buf_len: usize) -> Result<*mut LlmpMsg, AflError> {
        match self.alloc_next_if_space(buf_len) {
            Some(msg) => return Ok(msg),
            _ => (),
        };

        /* no more space left! We'll have to start a new page */
        self.handle_out_eop()?;

        match self.alloc_next_if_space(buf_len) {
            Some(msg) => Ok(msg),
            None => Err(AflError::Unknown(format!(
                "Error allocating {} bytes in shmap",
                buf_len
            ))),
        }
    }

    /// Cancel send of the next message, this allows us to allocate a new message without sending this one.
    pub unsafe fn cancel_send(&mut self, msg: *mut LlmpMsg) {
        /* DBG("Client %d cancels send of msg at %p with tag 0x%X and size %ld", client->id, msg, msg->tag,
         * msg->buf_len_padded); */
        let page = self.out_maps.last().unwrap().page();
        (*msg).tag = LLMP_TAG_UNSET;
        (*page).size_used -= (*msg).buf_len_padded as usize + size_of::<LlmpMsg>();
    }

    /// Allocates a message of the given size, tags it, and sends it off.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), AflError> {
        // Make sure we don't reuse already allocated tags
        if tag == LLMP_TAG_NEW_SHM_CLIENT
            || tag == LLMP_TAG_END_OF_PAGE
            || tag == LLMP_TAG_UNINITIALIZED
            || tag == LLMP_TAG_UNSET
        {
            return Err(AflError::Unknown(format!(
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
}

/// Receiving end of an llmp channel
impl LlmpReceiver {
    /// Read next message.
    unsafe fn recv(&mut self) -> Result<Option<*mut LlmpMsg>, AflError> {
        /* DBG("recv %p %p\n", page, last_msg); */
        compiler_fence(Ordering::SeqCst);
        let page = self.current_recv_map.page();
        let last_msg = self.last_msg_recvd;
        let current_msg_id = ptr::read_volatile(&mut (*page).current_msg_id);

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
                &self.current_recv_map,
                last_msg,
                size_of::<LlmpMsg>(),
            )?)
        };

        // Let's see what we go here.
        match ret {
            Some(msg) => {
                if !(*msg).in_map(&self.current_recv_map) {
                    return Err(AflError::IllegalState("Unexpected message in map (out of map bounds) - bugy client or tampered shared map detedted!".into()));
                }
                // Handle special, LLMP internal, messages.
                match (*msg).tag {
                    LLMP_TAG_UNSET => panic!("BUG: Read unallocated msg"),
                    LLMP_TAG_END_OF_PAGE => {
                        dbg!("Got end of page, allocing next");
                        // Handle end of page
                        if (*msg).buf_len < size_of::<LlmpPayloadSharedMapInfo>() as u64 {
                            panic!(format!(
                                "Illegal message length for EOP (is {}, expected {})",
                                (*msg).buf_len_padded,
                                size_of::<LlmpPayloadSharedMapInfo>()
                            ));
                        }
                        let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;

                        /* We can reuse the map mem space, no need to free and calloc.
                        However, the pageinfo points to the map we're about to unmap.
                        Clone the contents first to be safe (probably fine in rust eitner way). */
                        let pageinfo_cpy = (*pageinfo).clone();

                        // Mark the old page save to unmap, in case we didn't so earlier.
                        ptr::write_volatile(&mut (*page).save_to_unmap, 1);
                        // Map the new page. The old one should be unmapped by Drop
                        self.current_recv_map = LlmpSharedMap::from_name_slice(
                            &pageinfo_cpy.shm_str,
                            pageinfo_cpy.map_size,
                        )?;
                        // Mark the new page save to unmap also (it's mapped by us, the broker now)
                        ptr::write_volatile(&mut (*page).save_to_unmap, 1);

                        dbg!("Got a new recv map", self.current_recv_map.shmem.shm_str);
                        // After we mapped the new page, return the next message, if available
                        return self.recv();
                    }
                    _ => (),
                }

                // Store the last msg for next time
                self.last_msg_recvd = msg;
            }
            _ => (),
        };
        Ok(ret)
    }

    /// Blocks/spins until the next message gets posted to the page,
    /// then returns that message.
    pub unsafe fn recv_blocking(&mut self) -> Result<*mut LlmpMsg, AflError> {
        let mut current_msg_id = 0;
        let page = self.current_recv_map.page();
        let last_msg = self.last_msg_recvd;
        if !last_msg.is_null() {
            if (*last_msg).tag == LLMP_TAG_END_OF_PAGE && !llmp_msg_in_page(page, last_msg) {
                panic!("BUG: full page passed to await_message_blocking or reset failed");
            }
            current_msg_id = (*last_msg).message_id
        }
        loop {
            compiler_fence(Ordering::SeqCst);
            if ptr::read_volatile(&mut (*page).current_msg_id) != current_msg_id {
                return match self.recv()? {
                    Some(msg) => Ok(msg),
                    None => panic!("BUG: blocking llmp message should never be NULL"),
                };
            }
        }
    }

    /// Returns the next message, tag, buf, if avaliable, else None
    #[inline]
    pub fn recv_buf(&mut self) -> Result<Option<(u32, &[u8])>, AflError> {
        unsafe {
            Ok(match self.recv()? {
                Some(msg) => Some(((*msg).tag, (*msg).as_slice(&self.current_recv_map)?)),
                None => None,
            })
        }
    }

    /// Returns the next message, tag, buf, looping until it becomes available
    #[inline]
    pub fn recv_buf_blocking(&mut self) -> Result<(u32, &[u8]), AflError> {
        unsafe {
            let msg = self.recv_blocking()?;
            Ok(((*msg).tag, (*msg).as_slice(&self.current_recv_map)?))
        }
    }
}

/// The page struct, placed on a shared mem instance.
impl LlmpSharedMap {
    /// Creates a new page with minimum prev_max_alloc_size or LLMP_PREF_INITIAL_MAP_SIZE
    /// returning the initialized shared mem struct
    pub fn new(sender: u32, min_size: usize) -> Result<Self, AflError> {
        // Create a new shard page.
        let mut shmem = AflShmem::new(new_map_size(min_size))?;
        unsafe {
            _llmp_page_init(&mut shmem, sender);
        }
        Ok(Self { shmem })
    }

    /// Initialize from a shm_str with fixed len of 20
    pub fn from_name_slice(shm_str: &[u8; 20], map_size: usize) -> Result<Self, AflError> {
        let shmem = AflShmem::from_name_slice(shm_str, map_size)?;
        // Not initializing the page here - the other side should have done it already!
        Ok(Self { shmem })
    }

    /// Get the unsafe ptr to this page, situated on the shared map
    pub unsafe fn page(&self) -> *mut LlmpPage {
        shmem2page(&self.shmem)
    }
}

/// The broker forwards all messages to its own bus-like broadcast map.
/// It may intercept messages passing through.
impl LlmpBroker {
    /// Create and initialize a new llmp_broker
    pub fn new() -> Result<Self, AflError> {
        let broker = LlmpBroker {
            llmp_out: LlmpSender {
                id: 0,
                last_msg_sent: ptr::null_mut(),
                out_maps: vec![LlmpSharedMap::new(0, 0)?],
                // Broker never cleans up the pages so that new
                // clients may join at any time
                keep_pages_forever: true,
            },
            msg_hooks: vec![],
            llmp_clients: vec![],
        };

        Ok(broker)
    }

    /// Allocate the next message on the outgoing map
    unsafe fn alloc_next(&mut self, buf_len: usize) -> Result<*mut LlmpMsg, AflError> {
        self.llmp_out.alloc_next(buf_len)
    }

    /// Registers a new client for the given sharedmap str and size.
    /// Returns the id of the new client in broker.client_map
    pub fn register_client(&mut self, client_page: LlmpSharedMap) {
        let id = self.llmp_clients.len() as u32;
        self.llmp_clients.push(LlmpReceiver {
            id,
            current_recv_map: client_page,
            last_msg_recvd: 0 as *mut LlmpMsg,
        });
    }

    /// Adds a hook that gets called in the broker for each new message the broker touches.
    /// if the callback returns false, the message is not forwarded to the clients. */
    pub fn add_message_hook(&mut self, hook: LlmpMsgHookFn) {
        self.msg_hooks.push(hook);
    }

    /// For internal use: Forward the current message to the out map.
    unsafe fn forward_msg(&mut self, msg: *mut LlmpMsg) -> Result<(), AflError> {
        let mut out: *mut LlmpMsg = self.alloc_next((*msg).buf_len_padded as usize)?;

        /* Copy over the whole message.
        If we should need zero copy, we could instead post a link to the
        original msg with the map_id and offset. */
        let actual_size = (*out).buf_len_padded;
        msg.copy_to_nonoverlapping(out, size_of::<LlmpMsg>() + (*msg).buf_len_padded as usize);
        (*out).buf_len_padded = actual_size;
        /* We need to replace the message ID with our own */
        match self.llmp_out.send(out) {
            Err(e) => panic!(format!("Error sending msg: {:?}", e)),
            _ => (),
        };
        self.llmp_out.last_msg_sent = out;
        Ok(())
    }

    /// broker broadcast to its own page for all others to read */
    #[inline]
    unsafe fn handle_new_msgs(&mut self, client_id: u32) -> Result<(), AflError> {
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
                    println!("Ignoring broken CLIENT_ADDED msg due to incorrect size. Expected {} but got {}",
                        (*msg).buf_len_padded,
                        size_of::<LlmpPayloadSharedMapInfo>()
                    );
                } else {
                    let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;

                    match LlmpSharedMap::from_name_slice(&(*pageinfo).shm_str, (*pageinfo).map_size)
                    {
                        Ok(new_page) => {
                            let id = next_id;
                            next_id += 1;
                            self.llmp_clients.push(LlmpReceiver {
                                id,
                                current_recv_map: new_page,
                                last_msg_recvd: 0 as *mut LlmpMsg,
                            });
                        }
                        Err(e) => println!("Error adding client! {:?}", e),
                    };
                }
            } else {
                // The message is not specifically for use. Let the user handle it, then forward it to the clients, if necessary.
                let mut should_forward_msg = true;
                for hook in &self.msg_hooks {
                    match (hook)(client_id, msg) {
                        LlmpMsgHookResult::Handled => should_forward_msg = false,
                        _ => (),
                    }
                }
                if should_forward_msg {
                    self.forward_msg(msg)?;
                }
            }
        }
    }

    /// The broker walks all pages and looks for changes, then broadcasts them on
    /// its own shared page, once.
    #[inline]
    pub fn once(&mut self) -> Result<(), AflError> {
        compiler_fence(Ordering::SeqCst);
        for i in 0..self.llmp_clients.len() {
            unsafe {
                self.handle_new_msgs(i as u32)?;
            }
        }
        Ok(())
    }

    /// Loops infinitely, forwarding and handling all incoming messages from clients.
    /// Never returns. Panics on error.
    /// 5 millis of sleep can't hurt to keep busywait not at 100%
    pub fn loop_forever(&mut self, sleep_time: Option<Duration>) -> ! {
        loop {
            compiler_fence(Ordering::SeqCst);
            self.once()
                .expect("An error occurred when brokering. Exiting.");
            match sleep_time {
                Some(time) => thread::sleep(time),
                None => (),
            }
        }
    }

    /// Launches a thread using a tcp listener socket, on which new clients may connect to this broker
    /// Does so on the given port.
    pub fn launch_tcp_listener_on(
        &mut self,
        port: u16,
    ) -> Result<thread::JoinHandle<()>, AflError> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
        // accept connections and process them, spawning a new thread for each one
        println!("Server listening on port {}", port);
        return self.launch_tcp_listener(listener);
    }

    /// Launches a thread using a tcp listener socket, on which new clients may connect to this broker
    pub fn launch_tcp_listener(
        &mut self,
        listener: TcpListener,
    ) -> Result<thread::JoinHandle<()>, AflError> {
        // Later in the execution, after the initial map filled up,
        // the current broacast map will will point to a different map.
        // However, the original map is (as of now) never freed, new clients will start
        // to read from the initial map id.

        let client_out_map_mem = &self.llmp_out.out_maps.first().unwrap().shmem;
        let broadcast_str_initial = client_out_map_mem.shm_str.clone();

        let llmp_tcp_id = self.llmp_clients.len() as u32;

        // Tcp out map sends messages from background thread tcp server to foreground client
        let tcp_out_map = LlmpSharedMap::new(llmp_tcp_id, LLMP_PREF_INITIAL_MAP_SIZE)?;
        let tcp_out_map_str = tcp_out_map.shmem.shm_str;
        let tcp_out_map_size = tcp_out_map.shmem.map_size;
        self.register_client(tcp_out_map);

        Ok(thread::spawn(move || {
            let mut new_client_sender = LlmpSender {
                id: 0,
                last_msg_sent: 0 as *mut LlmpMsg,
                out_maps: vec![
                    LlmpSharedMap::from_name_slice(&tcp_out_map_str, tcp_out_map_size).unwrap(),
                ],
                // drop pages to the broker if it already read them
                keep_pages_forever: false,
            };

            loop {
                let (mut stream, addr) = match listener.accept() {
                    Ok(res) => res,
                    Err(e) => {
                        dbg!("Ignoring failed accept", e);
                        continue;
                    }
                };
                dbg!("New connection", addr, stream.peer_addr().unwrap());
                match stream.write(&broadcast_str_initial) {
                    Ok(_) => {} // fire & forget
                    Err(e) => {
                        dbg!("Could not send to shmap to client", e);
                        continue;
                    }
                };
                let mut new_client_map_str: [u8; 20] = Default::default();
                match stream.read_exact(&mut new_client_map_str) {
                    Ok(()) => (),
                    Err(e) => {
                        dbg!("Ignoring failed read from client", e);
                        continue;
                    }
                };

                unsafe {
                    let msg = new_client_sender
                        .alloc_next(size_of::<LlmpPayloadSharedMapInfo>())
                        .expect("Could not allocate a new message in shared map.");
                    (*msg).tag = LLMP_TAG_NEW_SHM_CLIENT;
                    let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMapInfo;
                    (*pageinfo).shm_str = new_client_map_str;
                    (*pageinfo).map_size = LLMP_PREF_INITIAL_MAP_SIZE;
                    match new_client_sender.send(msg) {
                        Ok(()) => (),
                        Err(e) => println!("Error forwarding client on map: {:?}", e),
                    };
                }
            }
        }))
    }

    /// Broadcasts the given buf to all lients
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), AflError> {
        self.llmp_out.send_buf(tag, buf)
    }
}

/// `n` clients connect to a broker. They share an outgoing map with the broker,
/// and get incoming messages from the shared broker bus
impl LlmpClient {
    /// Creates a new LlmpClient
    pub fn new(initial_broker_map: LlmpSharedMap) -> Result<Self, AflError> {
        Ok(Self {
            llmp_out: LlmpSender {
                id: 0,
                last_msg_sent: 0 as *mut LlmpMsg,
                out_maps: vec![LlmpSharedMap::new(0, LLMP_PREF_INITIAL_MAP_SIZE)?],
                // drop pages to the broker if it already read them
                keep_pages_forever: false,
            },
            llmp_in: LlmpReceiver {
                id: 0,
                current_recv_map: initial_broker_map,
                last_msg_recvd: 0 as *mut LlmpMsg,
            },
        })
    }

    pub fn create_attach_to_tcp(port: u16) -> Result<Self, AflError> {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;
        println!("Connected to port {}", port);

        let mut new_broker_map_str: [u8; 20] = Default::default();
        stream.read_exact(&mut new_broker_map_str)?;

        let ret = Self::new(LlmpSharedMap::from_name_slice(
            &new_broker_map_str,
            LLMP_PREF_INITIAL_MAP_SIZE,
        )?)?;

        stream.write(&ret.llmp_out.out_maps.first().unwrap().shmem.shm_str)?;
        Ok(ret)
    }

    /// Commits a msg to the client's out map
    pub unsafe fn send(&mut self, msg: *mut LlmpMsg) -> Result<(), AflError> {
        self.llmp_out.send(msg)
    }

    /// Allocates a message of the given size, tags it, and sends it off.
    pub fn send_buf(&mut self, tag: Tag, buf: &[u8]) -> Result<(), AflError> {
        self.llmp_out.send_buf(tag, buf)
    }

    /// Informs the broker about a new client in town, with the given map id
    pub fn send_client_added_msg(
        &mut self,
        shm_str: &[u8; 20],
        shm_id: usize,
    ) -> Result<(), AflError> {
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
    #[inline]
    pub unsafe fn recv(&mut self) -> Result<Option<*mut LlmpMsg>, AflError> {
        self.llmp_in.recv()
    }

    /// A client blocks/spins until the next message gets posted to the page,
    /// then returns that message.
    #[inline]
    pub unsafe fn recv_blocking(&mut self) -> Result<*mut LlmpMsg, AflError> {
        self.llmp_in.recv_blocking()
    }

    /// The current page could have changed in recv (EOP)
    /// Alloc the next message, internally handling end of page by allocating a new one.
    #[inline]
    pub unsafe fn alloc_next(&mut self, buf_len: usize) -> Result<*mut LlmpMsg, AflError> {
        self.llmp_out.alloc_next(buf_len)
    }

    /// Returns the next message, tag, buf, if avaliable, else None
    #[inline]
    pub fn recv_buf(&mut self) -> Result<Option<(u32, &[u8])>, AflError> {
        self.llmp_in.recv_buf()
    }

    /// Receives a buf from the broker, looping until a messages becomes avaliable
    #[inline]
    pub fn recv_buf_blocking(&mut self) -> Result<(u32, &[u8]), AflError> {
        self.llmp_in.recv_buf_blocking()
    }
}
