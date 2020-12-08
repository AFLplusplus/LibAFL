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

use ::libc;

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};
use core::{ffi::c_void, time};
use libc::{c_int, c_uint, c_ulong, c_ushort};
use std::{cmp::max, ffi::CStr, mem::size_of, os::raw::c_char, thread};

use crate::utils::next_pow2;
use crate::AflError;

use super::shmem_translated::{afl_shmem_by_str, afl_shmem_deinit, afl_shmem_init, AflShmem};

/// The header length of a llmp page in a shared map (until messages start)
const LLMP_PAGE_HEADER_LEN: usize = offset_of!(LlmpPage, messages);

/// We'll start off with 256 megabyte maps per fuzzer
const LLMP_INITIAL_MAP_SIZE: usize = 1 << 28;

/// A msg fresh from the press: No tag got sent by the user yet
const LLMP_TAG_UNSET: u32 = 0xdeadaf;
/// This message should not exist yet. Some bug in unsafe code!
const LLMP_TAG_UNINITIALIZED: u32 = 0xa143af11;
/// The end of page mesasge
/// When receiving this, a new sharedmap needs to be allocated.
const LLMP_TAG_END_OF_PAGE: u32 = 0xaf1e0f1;
/// A new client for this broekr got added.
const LLMP_TAG_NEW_SHM_CLIENT: u32 = 0xc11e471;

extern "C" {
    #[no_mangle]
    fn memcpy(_: *mut c_void, _: *const c_void, _: c_ulong) -> *mut c_void;
    #[no_mangle]
    fn memmove(_: *mut c_void, _: *const c_void, _: c_ulong) -> *mut c_void;
    #[no_mangle]
    fn memset(_: *mut c_void, _: c_int, _: c_ulong) -> *mut c_void;
}

pub type AflRet = c_uint;
pub const AFL_RET_ALLOC: AflRet = 3;
pub const AFL_RET_SUCCESS: AflRet = 0;

#[derive(Clone)]
pub struct LlmpSender {
    pub id: u32,
    pub last_msg_sent: *mut LlmpMsg,
    pub out_maps: Vec<LlmpPageWrapper>,
}

#[derive(Clone)]
pub struct LlmpClient {
    pub llmp_out: LlmpSender,
    pub last_msg_recvd: *mut LlmpMsg,
    pub current_broadcast_map: LlmpPageWrapper,
    pub last_msg_sent: *mut LlmpMsg,
    pub out_maps: Vec<LlmpPageWrapper>,
    pub new_out_page_hooks: Vec<LlmpHookdataGeneric<LlmpClientNewPageHookFn>>,
}

#[derive(Clone)]
struct LlmpPageWrapper {
    shmem: AflShmem,
}

/// The page struct, placed on a shared mem instance.
impl LlmpPageWrapper {
    /// Creates a new page with minimum prev_max_alloc_size or LLMP_INITIAL_MAP_SIZE
    /// returning the initialized shared mem struct
    unsafe fn new(sender: u32, min_size: usize) -> Result<Self, AflError> {
        // Create a new shard page.
        let mut shmem = AflShmem::new(new_map_size(min_size))?;
        _llmp_page_init(&mut shmem, sender);
        Ok(Self { shmem })
    }

    /// Initialize from a 0-terminated sharedmap id string and its size
    unsafe fn from_str(shm_str: &CStr, map_size: usize) -> Result<Self, AflError> {
        let shmem = AflShmem::from_str(shm_str, map_size)?;
        // Not initializing the page here - the other side should have done it already!
        Ok(Self { shmem })
    }

    /// Initialize from a shm_str with fixed len of 20
    unsafe fn from_name_slice(shm_str: &[u8; 20], map_size: usize) -> Result<Self, AflError> {
        let shmem = AflShmem::from_name_slice(shm_str, map_size)?;
        // Not initializing the page here - the other side should have done it already!
        Ok(Self { shmem })
    }

    unsafe fn page(&self) -> *mut LlmpPage {
        shmem2page(&self.shmem)
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct LlmpHookdataGeneric<T> {
    pub func: T,
    pub data: *mut c_void,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct LlmpMsg {
    pub tag: u32,
    pub sender: u32,
    pub message_id: u64,
    pub buf_len: u64,
    pub buf_len_padded: u64,
    pub buf: [u8; 0],
}

#[derive(Clone)]
#[repr(C)]
pub struct LlmpBroker {
    pub llmp_out: LlmpSender,
    pub msg_hooks: Vec<LlmpHookdataGeneric<LlmpMsgHookFn>>,
    pub llmp_clients: Vec<LlmpBrokerClientMetadata>,
}

#[derive(Clone)]
#[repr(C)]
pub struct LlmpBrokerClientMetadata {
    pub id: u32,
    pub cur_client_map: LlmpPageWrapper,
    pub last_msg_broker_read: *mut LlmpMsg,
    pub clientloop: Option<LlmpClientloopFn>,
    pub data: *mut c_void,
}

/// The client loop, running for each spawned client
pub type LlmpClientloopFn = unsafe fn(client: *mut LlmpClient, data: *mut c_void) -> !;

/// A share mem page, as used by llmp internally
#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct LlmpPage {
    pub sender: u32,
    pub save_to_unmap: c_ushort,
    pub sender_dead: c_ushort,
    pub current_msg_id: u64,
    pub size_total: usize,
    pub size_used: usize,
    pub max_alloc_size: usize,
    pub messages: [LlmpMsg; 0],
}

/// Result of an LLMP Mesasge hook
pub enum LlmpMsgHookResult {
    /// This has been handled in the broker. No need to forward.
    Handled,
    /// Forward this to the clients. We are not done here.
    ForwardToClients,
}

/// Message Hook
pub type LlmpMsgHookFn = unsafe fn(
    broker: &LlmpBroker,
    client_data: &LlmpBrokerClientMetadata,
    msg: *mut LlmpMsg,
    data: *mut c_void,
) -> LlmpMsgHookResult;

/// Hook that gets called for each new page, created by LLMP
pub type LlmpClientNewPageHookFn = unsafe fn(client: &LlmpClient) -> ();

/// Message payload when a client got added LLMP_TAG_CLIENT_ADDED_V1 */
/// This is an internal message!
/// LLMP_TAG_END_OF_PAGE_V1
#[derive(Copy, Clone)]
#[repr(C, packed)]
struct LlmpPayloadSharedMap {
    pub map_size: usize,
    pub shm_str: [u8; 20],
}

#[inline]
unsafe fn shmem2page(afl_shmem: &AflShmem) -> *mut LlmpPage {
    afl_shmem.map as *mut LlmpPage
}

/* If a msg is contained in the current page */
unsafe fn llmp_msg_in_page(page: *mut LlmpPage, msg: *mut LlmpMsg) -> bool {
    /* DBG("llmp_msg_in_page %p within %p-%p\n", msg, page, page + page->size_total); */
    return (page as *mut u8) < msg as *mut u8
        && (page as *mut u8).offset((*page).size_total as isize) > msg as *mut u8;
}

/// What byte count to align messages to
/// LlmpMsg sizes (including header) will always be rounded up to be a multiple of this value
const LLMP_ALIGNNMENT: usize = 64;

/// Size of a new page message, header, payload, and alignment
const EOP_MSG_SIZE: usize = llmp_align(size_of::<LlmpMsg>() + size_of::<LlmpPayloadSharedMap>());

/* allign to LLMP_ALIGNNMENT=64 bytes */
#[inline]
const fn llmp_align(to_align: usize) -> usize {
    // check if we need to align first
    if LLMP_ALIGNNMENT == 0 {
        return to_align;
    }
    // Then do the alignment
    let modulo = to_align % LLMP_ALIGNNMENT;
    if modulo == 0 {
        to_align
    } else {
        to_align + LLMP_ALIGNNMENT - modulo
    }
}

/// In case we don't have enough space, make sure the next page will be large
/// enough. For now, we want to have at least enough space to store 2 of the
/// largest messages we encountered (plus message one new_page message).
#[inline]
const fn new_map_size(max_alloc: usize) -> usize {
    next_pow2(max(
        max_alloc * 2 + EOP_MSG_SIZE + LLMP_PAGE_HEADER_LEN,
        LLMP_INITIAL_MAP_SIZE,
    ) as u64) as usize
}

/* Initialize a new llmp_page. size should be relative to
 * llmp_page->messages */
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

/* Pointer to the message behind the last message */
#[inline]
const unsafe fn _llmp_next_msg_ptr(last_msg: *const LlmpMsg) -> *mut LlmpMsg {
    /* DBG("_llmp_next_msg_ptr %p %lu + %lu\n", last_msg, last_msg->buf_len_padded, sizeof(llmp_message)); */
    return (last_msg as *mut u8)
        .offset(size_of::<LlmpMsg>() as isize)
        .offset((*last_msg).buf_len_padded as isize) as *mut LlmpMsg;
}

/* Read next message. */
unsafe fn llmp_recv(
    page_wrapper: &LlmpPageWrapper,
    last_msg: *mut LlmpMsg,
) -> Option<*mut LlmpMsg> {
    /* DBG("llmp_recv %p %p\n", page, last_msg); */
    compiler_fence(Ordering::SeqCst);
    let page = page_wrapper.page();
    let current_msg_id = ptr::read_volatile(&mut (*page).current_msg_id);
    if current_msg_id == 0 {
        /* No messages yet */
        None
    } else if last_msg.is_null() {
        /* We never read a message from this queue. Return first. */
        Some((*page).messages.as_mut_ptr())
    } else if (*last_msg).message_id == current_msg_id {
        /* Oops! No new message! */
        None
    } else {
        Some(_llmp_next_msg_ptr(last_msg))
    }
}

/* Blocks/spins until the next message gets posted to the page,
then returns that message. */
pub unsafe fn llmp_recv_blocking(
    page_wrapper: &LlmpPageWrapper,
    last_msg: *mut LlmpMsg,
) -> *mut LlmpMsg {
    let mut current_msg_id = 0;
    let page = page_wrapper.page();
    if !last_msg.is_null() {
        if (*last_msg).tag == LLMP_TAG_END_OF_PAGE && !llmp_msg_in_page(page, last_msg) {
            panic!("BUG: full page passed to await_message_blocking or reset failed");
        }
        current_msg_id = (*last_msg).message_id
    }
    loop {
        compiler_fence(Ordering::SeqCst);
        if ptr::read_volatile(&mut (*page).current_msg_id) != current_msg_id {
            return match llmp_recv(page_wrapper, last_msg) {
                Some(msg) => msg,
                None => panic!("BUG: blocking llmp message should never be NULL"),
            };
        }
    }
}

/* Special allocation function for EOP messages (and nothing else!)
  The normal alloc will fail if there is not enough space for buf_len_padded + EOP
  So if llmp_alloc_next fails, create new page if necessary, use this function,
  place EOP, commit EOP, reset, alloc again on the new space.
*/
unsafe fn llmp_alloc_eop(page: *mut LlmpPage, last_msg: *const LlmpMsg) -> *mut LlmpMsg {
    if (*page).size_used + EOP_MSG_SIZE > (*page).size_total {
        panic!(format!("PROGRAM ABORT : BUG: EOP does not fit in page! page {:?}, size_current {:?}, size_total {:?}", page,
               (*page).size_used, (*page).size_total));
    }
    let mut ret: *mut LlmpMsg = if !last_msg.is_null() {
        _llmp_next_msg_ptr(last_msg)
    } else {
        (*page).messages.as_mut_ptr()
    };
    if (*ret).tag == LLMP_TAG_UNINITIALIZED {
        panic!("Did not call send() on last message!");
    }
    (*ret).buf_len_padded = size_of::<LlmpPayloadSharedMap>() as c_ulong;
    (*ret).message_id = if !last_msg.is_null() {
        (*last_msg).message_id + 1
    } else {
        1
    };
    (*ret).tag = LLMP_TAG_END_OF_PAGE;
    (*page).size_used += EOP_MSG_SIZE;
    ret
}

/// Will return a ptr to the next msg buf, or None if map is full.
/// Never call alloc_next without either sending or cancelling the last allocated message for this page!
/// There can only ever be up to one message allocated per page at each given time.
unsafe fn llmp_alloc_next(llmp: &mut LlmpSender, buf_len: usize) -> Option<*mut LlmpMsg> {
    let mut buf_len_padded = buf_len;
    let mut complete_msg_size = llmp_align(size_of::<LlmpMsg>() + buf_len_padded);
    let page = llmp.out_maps.last().unwrap().page();
    let last_msg = llmp.last_msg_sent;
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
        panic!(format!("BUG: The current message never got commited using llmp_send! (page->current_msg_id {:?}, last_msg->message_id: {})", (*page).current_msg_id, (*last_msg).message_id));
    } else {
        buf_len_padded = complete_msg_size - size_of::<LlmpMsg>();
        /* DBG("XXX ret %p id %u buf_len_padded %lu complete_msg_size %lu\n", ret, ret->message_id, buf_len_padded,
         * complete_msg_size); */

        /* Still space for the new message plus the additional "we're full" message? */
        if (*page).size_used + complete_msg_size + EOP_MSG_SIZE > (*page).size_total {
            /* We're full. */
            return None;
        }
        ret = _llmp_next_msg_ptr(last_msg);
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
    (*ret).buf_len_padded = buf_len_padded as c_ulong;
    (*ret).buf_len = buf_len as c_ulong;
    /* DBG("Returning new message at %p with len %ld, TAG was %x", ret, ret->buf_len_padded, ret->tag); */
    /* Maybe catch some bugs... */
    (*_llmp_next_msg_ptr(ret)).tag = LLMP_TAG_UNSET;
    (*ret).tag = LLMP_TAG_UNINITIALIZED;
    Some(ret)
}

/// Commit the message last allocated by llmp_alloc_next to the queue.
/// After commiting, the msg shall no longer be altered!
/// It will be read by the consuming threads (broker->clients or client->broker)
unsafe fn llmp_send(page: *mut LlmpPage, msg: *mut LlmpMsg) -> Result<(), AflError> {
    if (*msg).tag == LLMP_TAG_UNSET as c_uint {
        panic!(format!(
            "No tag set on message with id {}",
            (*msg).message_id
        ));
    }
    if msg.is_null() || !llmp_msg_in_page(page, msg) {
        return Err(AflError::Unknown(format!(
            "Llmp Message {:?} is null or not in current page",
            msg
        )));
    }
    compiler_fence(Ordering::SeqCst);
    ptr::write_volatile(&mut (*page).current_msg_id, (*msg).message_id);
    compiler_fence(Ordering::SeqCst);
    Ok(())
}

/// listener about it using a EOP message.
unsafe fn llmp_handle_out_eop(llmp: &mut LlmpSender) -> Result<(), AflError> {
    let map_count = llmp.out_maps.len();
    let mut old_map = llmp.out_maps.last_mut().unwrap().page();

    // Create a new shard page.
    let mut new_map_shmem = LlmpPageWrapper::new((*old_map).sender, (*old_map).max_alloc_size)?;
    let mut new_map = new_map_shmem.page();

    ptr::write_volatile(&mut (*new_map).current_msg_id, (*old_map).current_msg_id);
    (*new_map).max_alloc_size = (*old_map).max_alloc_size;
    /* On the old map, place a last message linking to the new map for the clients
     * to consume */
    let mut out: *mut LlmpMsg = llmp_alloc_eop(old_map, llmp.last_msg_sent);
    (*out).sender = (*old_map).sender;

    let mut end_of_page_msg = (*out).buf.as_mut_ptr() as *mut LlmpPayloadSharedMap;
    (*end_of_page_msg).map_size = new_map_shmem.shmem.map_size;
    (*end_of_page_msg).shm_str = new_map_shmem.shmem.shm_str;

    // We never sent a msg on the new buf */
    llmp.last_msg_sent = 0 as *mut LlmpMsg;

    /* Send the last msg on the old buf */
    llmp_send(old_map, out)?;
    llmp.out_maps.push(new_map_shmem);

    Ok(())
}

pub unsafe fn llmp_broker_alloc_next(
    broker: &LlmpBroker,
    len: usize,
) -> Result<*mut LlmpMsg, AflError> {
    match llmp_alloc_next(&mut broker.llmp_out, len) {
        Some(msg) => return Ok(msg),
        _ => (),
    };

    /* no more space left! We'll have to start a new page */
    llmp_handle_out_eop(&mut broker.llmp_out);

    match llmp_alloc_next(&mut broker.llmp_out, len) {
        Some(msg) => Ok(msg),
        None => Err(AflError::Unknown(format!(
            "Error allocating {} bytes in shmap",
            len
        ))),
    }
}

impl LlmpBroker {
    /// Create and initialize a new llmp_broker
    pub unsafe fn new() -> Result<Self, AflError> {
        let mut broker = LlmpBroker {
            llmp_out: LlmpSender {
                id: 0,
                last_msg_sent: ptr::null_mut(),
                out_maps: vec![LlmpPageWrapper::new(0, 0)?],
            },
            msg_hooks: vec![],
            llmp_clients: vec![],
        };

        Ok(broker)
    }

    /// Registers a new client for the given sharedmap str and size.
    /// Returns the id of the new client in broker.client_map
    unsafe fn register_client(&mut self, client_page: LlmpPageWrapper) {
        let id = self.llmp_clients.len() as u32;
        self.llmp_clients.push(LlmpBrokerClientMetadata {
            id,
            cur_client_map: client_page,
            last_msg_broker_read: 0 as *mut LlmpMsg,
            clientloop: None,
            data: 0 as *mut c_void,
        });
    }

    /// Adds a hook that gets called in the broker for each new message the broker touches.
    /// if the callback returns false, the message is not forwarded to the clients. */
    pub fn add_message_hook(&mut self, hook: LlmpMsgHookFn, data: *mut c_void) {
        self.msg_hooks
            .push(LlmpHookdataGeneric { func: hook, data });
    }

    /// For internal use: Forward the current message to the out map.
    unsafe fn forward_msg(&mut self, msg: *mut LlmpMsg) -> Result<(), AflError> {
        let mut out: *mut LlmpMsg = llmp_broker_alloc_next(self, (*msg).buf_len_padded as usize)?;

        /* Copy over the whole message.
        If we should need zero copy, we could instead post a link to the
        original msg with the map_id and offset. */
        let actual_size = (*out).buf_len_padded;
        memcpy(
            out as *mut c_void,
            msg as *const c_void,
            size_of::<LlmpMsg>() as c_ulong + (*msg).buf_len_padded as c_ulong,
        );
        (*out).buf_len_padded = actual_size;
        /* We need to replace the message ID with our own */
        let out_page = self.llmp_out.out_maps.last().unwrap().page();
        (*out).message_id = (*out_page).current_msg_id + 1;
        match llmp_send(out_page, out) {
            Err(e) => panic!(format!("Error sending msg: {:?}", e)),
            _ => (),
        };
        self.llmp_out.last_msg_sent = out;
        Ok(())
    }

    /// broker broadcast to its own page for all others to read */
    unsafe fn handle_new_msgs(
        &mut self,
        client: &LlmpBrokerClientMetadata,
    ) -> Result<(), AflError> {
        // TODO: We could memcpy a range of pending messages, instead of one by one.
        /* DBG("llmp_broker_handle_new_msgs %p %p->%u\n", broker, client, client->client_state->id); */
        let incoming: *mut LlmpPage = client.cur_client_map.page();
        let mut current_message_id = if client.last_msg_broker_read.is_null() {
            0
        } else {
            (*client.last_msg_broker_read).message_id
        };

        while current_message_id != ptr::read_volatile(&(*incoming).current_msg_id) {
            let msg = match llmp_recv(&client.cur_client_map, (*client).last_msg_broker_read) {
                None => {
                    panic!("No message received but not all message ids receved! Data out of sync?")
                }
                Some(msg) => msg,
            };
            if (*msg).tag == LLMP_TAG_END_OF_PAGE {
                // Handle end of page
                if (*msg).buf_len < size_of::<LlmpPayloadSharedMap>() as u64 {
                    panic!(format!(
                        "Illegal message length for EOP (is {}, expected {})",
                        (*msg).buf_len_padded,
                        size_of::<LlmpPayloadSharedMap>()
                    ));
                }
                let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMap;

                /* We can reuse the map mem space, no need to free and calloc.
                However, the pageinfo points to the map we're about to unmap.
                Clone the contents first to be safe (probably fine in rust eitner way). */
                let mut pageinfo_cpy = (*pageinfo).clone();

                let client_map = (*client).cur_client_map;

                ptr::write_volatile(&mut (*client_map.page()).save_to_unmap, 1);
                client.cur_client_map =
                    LlmpPageWrapper::from_name_slice(&pageinfo_cpy.shm_str, pageinfo_cpy.map_size)?;
                dbg!("Client got a new map", client.cur_client_map.shmem.shm_str);
            } else if (*msg).tag == LLMP_TAG_NEW_SHM_CLIENT {
                /* This client informs us about yet another new client
                add it to the list! Also, no need to forward this msg. */
                if (*msg).buf_len < size_of::<LlmpPayloadSharedMap>() as u64 {
                    println!("Ignoring broken CLIENT_ADDED msg due to incorrect size. Expected {} but got {}",
                        (*msg).buf_len_padded,
                        size_of::<LlmpPayloadSharedMap>()
                    );
                } else {
                    let pageinfo = (*msg).buf.as_mut_ptr() as *mut LlmpPayloadSharedMap;

                    let client_id: u32 = client.id;
                    match LlmpPageWrapper::from_name_slice(
                        &(*pageinfo).shm_str,
                        (*pageinfo).map_size,
                    ) {
                        Ok(new_page) => self.register_client(new_page),
                        Err(e) => println!("Error adding client! {:?}", e),
                    };
                }
            } else {
                // The message is not specifically for use. Let the user handle it, then forward it to the clients, if necessary.
                let mut should_forward_msg = true;
                for hook in self.msg_hooks {
                    match (hook.func)(&self, client, msg, hook.data) {
                        LlmpMsgHookResult::Handled => should_forward_msg = false,
                        _ => (),
                    }
                }
                if should_forward_msg {
                    self.forward_msg(msg);
                }
            }
            (*client).last_msg_broker_read = msg;
            current_message_id = (*msg).message_id
        }
        Ok(())
    }

    /// The broker walks all pages and looks for changes, then broadcasts them on
    /// its own shared page, once.
    pub unsafe fn once(&mut self) {
        compiler_fence(Ordering::SeqCst);
        let mut i: u32 = 0;
        for client in self.llmp_clients {
            self.handle_new_msgs(&client);
        }
    }

    /// Loops infinitely, forwarding and handling all incoming messages from clients.
    /// Never returns.
    pub unsafe fn broker_loop(&mut self) -> ! {
        loop {
            compiler_fence(Ordering::SeqCst);
            self.once();

            /* 5 milis of sleep for now to not busywait at 100% */
            thread::sleep(time::Duration::from_millis(5));
        }
    }
}

/// A new page will be used. Notify each registered hook in the client about this fact.
unsafe fn llmp_clien_trigger_new_out_page_hooks(client: &LlmpClient) {
    for hook in client.new_out_page_hooks {
        (hook.func)(client);
    }
}

/// A wrapper around unpacking the data, calling through to the loop
unsafe fn _llmp_client_wrapped_loop(llmp_client_broker_metadata_ptr: *mut c_void) -> ! {
    let metadata: *mut LlmpBrokerClientMetadata =
        llmp_client_broker_metadata_ptr as *mut LlmpBrokerClientMetadata;
    /* Before doing anything else:, notify registered hooks about the new page we're about to use */
    llmp_clien_trigger_new_out_page_hooks((*metadata).client_state);

    (*metadata).clientloop.expect("non-null function pointer")(
        (*metadata).client_state,
        (*metadata).data,
    );
}

/// For non zero-copy, we want to get rid of old pages with duplicate messages
/// eventually. This function This funtion sees if we can unallocate older pages.
/// The broker would have informed us by setting the save_to_unmap-flag.
unsafe fn llmp_client_prune_old_pages(client: *mut LlmpClient) {
    let current_map: *mut u8 = (*(*client)
        .out_maps
        .offset((*client).out_map_count.wrapping_sub(1 as c_ulong) as isize))
    .map;
    /* look for pages that are save_to_unmap, then unmap them. */
    while (*(*client).out_maps.offset(0 as isize)).map != current_map
        && (*shmem2page(&mut *(*client).out_maps.offset(0 as isize))).save_to_unmap as c_int != 0
    {
        /* This page is save to unmap. The broker already reads or read it. */
        afl_shmem_deinit(&mut *(*client).out_maps.offset(0 as isize));
        /* We remove at the start, move the other pages back. */
        memmove(
            (*client).out_maps as *mut c_void,
            (*client).out_maps.offset(1 as isize) as *const c_void,
            (*client)
                .out_map_count
                .wrapping_sub(1 as c_ulong)
                .wrapping_mul(::std::mem::size_of::<AflShmem>() as c_ulong),
        );
        (*client).out_map_count = (*client).out_map_count.wrapping_sub(1)
    }
}

/// We don't have any space. Send eop, then continue on a new page.
unsafe fn llmp_client_handle_out_eop(client: *mut LlmpClient) -> bool {
    (*client).out_maps = llmp_handle_out_eop(
        (*client).out_maps,
        &mut (*client).out_map_count,
        &mut (*client).last_msg_sent,
    );
    if (*client).out_maps.is_null() {
        return 0 as c_int != 0;
    }
    /* Prune old pages!
      This is a good time to see if we can unallocate older pages.
      The broker would have informed us by setting the flag
    */
    llmp_client_prune_old_pages(client);
    /* So we got a new page. Inform potential hooks */
    llmp_clien_trigger_new_out_page_hooks(client);
    return 1 as c_int != 0;
}

/// A client receives a broadcast message.
/// Returns null if no message is availiable
pub unsafe fn llmp_client_recv(client: *mut LlmpClient) -> *mut LlmpMsg {
    loop {
        let msg = llmp_recv(
            shmem2page((*client).current_broadcast_map),
            (*client).last_msg_recvd,
        );
        if msg.is_null() {
            return 0 as *mut LlmpMsg;
        }
        (*client).last_msg_recvd = msg;
        if (*msg).tag == LLMP_TAG_UNSET as c_uint {
            panic!("BUG: Read unallocated msg");
        } else {
            if (*msg).tag == LLMP_TAG_END_OF_PAGE as c_uint {
                /* we reached the end of the current page.
                We'll init a new page but can reuse the mem are of the current map.
                However, we cannot use the message if we deinit its page, so let's copy */
                let mut pageinfo_cpy: LlmpPayloadSharedMap = LlmpPayloadSharedMap {
                    map_size: 0,
                    shm_str: [0; 20],
                };
                let broadcast_map: *mut AflShmem = (*client).current_broadcast_map;
                let pageinfo: *mut LlmpPayloadSharedMap = {
                    let mut _msg: *mut LlmpMsg = msg;
                    (if (*_msg).buf_len >= ::std::mem::size_of::<LlmpPayloadSharedMap>() as c_ulong
                    {
                        (*_msg).buf.as_mut_ptr()
                    } else {
                        0 as *mut u8
                    }) as *mut LlmpPayloadSharedMap
                };
                if pageinfo.is_null() {
                    panic!(format!(
                        "Illegal message length for EOP (is {}, expected {})",
                        (*msg).buf_len_padded,
                        ::std::mem::size_of::<LlmpPayloadSharedMap>() as c_ulong
                    ));
                }
                memcpy(
                    &mut pageinfo_cpy as *mut LlmpPayloadSharedMap as *mut c_void,
                    pageinfo as *const c_void,
                    ::std::mem::size_of::<LlmpPayloadSharedMap>() as c_ulong,
                );
                /* Never read by broker broker: shmem2page(map)->save_to_unmap = true; */
                afl_shmem_deinit(broadcast_map);
                if afl_shmem_by_str(
                    (*client).current_broadcast_map,
                    CStr::from_bytes_with_nul(&(*pageinfo).shm_str).expect("Illegal shm_str"),
                    (*pageinfo).map_size,
                )
                .is_null()
                {
                    panic!(format!(
                        "Could not get shmem by str for map {:?} of size {}",
                        (*pageinfo).shm_str.as_mut_ptr(),
                        (*pageinfo).map_size
                    ));
                }
            } else {
                return msg;
            }
        }
    }
}

/// A client blocks/spins until the next message gets posted to the page,
/// then returns that message.
pub unsafe fn llmp_client_recv_blocking(client: *mut LlmpClient) -> *mut LlmpMsg {
    let mut page: *mut LlmpPage = shmem2page((*client).current_broadcast_map);
    loop {
        compiler_fence(Ordering::SeqCst);
        /* busy-wait for a new msg_id to show up in the page */
        if (*page).current_msg_id
            != (if !(*client).last_msg_recvd.is_null() {
                (*(*client).last_msg_recvd).message_id
            } else {
                0 as c_uint
            }) as c_ulong
        {
            let ret: *mut LlmpMsg = llmp_client_recv(client);
            if !ret.is_null() {
                return ret;
            }
            /* last msg will exist, even if EOP was handled internally */
            page = shmem2page((*client).current_broadcast_map)
        }
    }
}

/// The current page could have changed in recv (EOP)
/// Alloc the next message, internally handling end of page by allocating a new one.
pub unsafe fn llmp_client_alloc_next(client: *mut LlmpClient, size: usize) -> *mut LlmpMsg {
    if client.is_null() {
        panic!("Client is NULL");
    }
    let mut msg = llmp_alloc_next(
        shmem2page(
            &mut *(*client)
                .out_maps
                .offset((*client).out_map_count.wrapping_sub(1) as isize),
        ),
        (*client).last_msg_sent,
        size as c_ulong,
    );
    if msg.is_null() {
        let last_map_count: c_ulong = (*client).out_map_count;
        /* Page is full -> Tell broker and start from the beginning.
        Also, pray the broker got all messaes we're overwriting. :) */
        if !llmp_client_handle_out_eop(client) {
            return 0 as *mut LlmpMsg;
        }
        if (*client).out_map_count == last_map_count
            || (*(*shmem2page(
                &mut *(*client)
                    .out_maps
                    .offset((*client).out_map_count.wrapping_sub(1) as isize),
            ))
            .messages
            .as_mut_ptr())
            .tag != LLMP_TAG_UNSET as c_uint
        {
            panic!("Error in handle_out_eop");
        }
        /* The client_out_map will have been changed by llmp_handle_out_eop. Don't
         * alias.
         */
        msg = llmp_alloc_next(
            shmem2page(
                &mut *(*client)
                    .out_maps
                    .offset((*client).out_map_count.wrapping_sub(1) as isize),
            ),
            0 as *mut LlmpMsg,
            size as c_ulong,
        );
        if msg.is_null() {
            return 0 as *mut LlmpMsg;
        }
    }
    (*msg).sender = (*client).id;
    (*msg).message_id = if !(*client).last_msg_sent.is_null() {
        (*(*client).last_msg_sent).message_id.wrapping_add(1)
    } else {
        1 as c_uint
    };
    /* DBG("Allocated message at loc %p with buflen %ld", msg, msg->buf_len_padded); */
    return msg;
}

/// Cancel send of the next message, this allows us to allocate a new message without sending this one.
pub unsafe fn llmp_client_cancel(client: *mut LlmpClient, mut msg: *mut LlmpMsg) {
    /* DBG("Client %d cancels send of msg at %p with tag 0x%X and size %ld", client->id, msg, msg->tag,
     * msg->buf_len_padded); */
    let mut page: *mut LlmpPage = shmem2page(
        &mut *(*client)
            .out_maps
            .offset((*client).out_map_count.wrapping_sub(1 as c_ulong) as isize),
    );
    (*msg).tag = LLMP_TAG_UNSET as c_uint;
    (*page).size_used = ((*page).size_used as c_ulong).wrapping_sub(
        (*msg)
            .buf_len_padded
            .wrapping_add(::std::mem::size_of::<LlmpMsg>() as c_ulong),
    ) as c_ulong;
}
/* Commits a msg to the client's out ringbuf */
pub unsafe fn llmp_client_send(
    client_state: *mut LlmpClient,
    msg: *mut LlmpMsg,
) -> Result<(), AflError> {
    let page: *mut LlmpPage = shmem2page(
        &mut *(*client_state)
            .out_maps
            .offset((*client_state).out_map_count.wrapping_sub(1) as isize),
    );
    llmp_send(page, msg)?;
    (*client_state).last_msg_sent = msg;
    Ok(())
}

/// Creates a new, unconnected, client state
pub unsafe fn llmp_client_new_unconnected() -> *mut LlmpClient {
    let client_state: *mut LlmpClient =
        calloc(1 as c_ulong, ::std::mem::size_of::<LlmpClient>() as c_ulong) as *mut LlmpClient;
    (*client_state).current_broadcast_map =
        calloc(1 as c_ulong, ::std::mem::size_of::<AflShmem>() as c_ulong) as *mut AflShmem;
    if (*client_state).current_broadcast_map.is_null() {
        return 0 as *mut LlmpClient;
    }
    (*client_state).out_maps = afl_realloc(
        (*client_state).out_maps as *mut c_void,
        (1 as c_ulong).wrapping_mul(::std::mem::size_of::<AflShmem>() as c_ulong),
    ) as *mut AflShmem;
    if (*client_state).out_maps.is_null() {
        free((*client_state).current_broadcast_map as *mut c_void);
        free(client_state as *mut c_void);
        return 0 as *mut LlmpClient;
    }
    (*client_state).out_map_count = 1 as c_ulong;
    if llmp_new_page_shmem(
        &mut *(*client_state).out_maps.offset(0 as isize),
        (*client_state).id as c_ulong,
        LLMP_INITIAL_MAP_SIZE,
    )
    .is_null()
    {
        afl_free((*client_state).out_maps as *mut c_void);
        free((*client_state).current_broadcast_map as *mut c_void);
        free(client_state as *mut c_void);
        return 0 as *mut LlmpClient;
    }
    (*client_state).new_out_page_hook_count = 0 as c_ulong;
    (*client_state).new_out_page_hooks = 0 as *mut LlmpHookdataGeneric;
    return client_state;
}

/// Destroys the given cient state
pub unsafe fn llmp_client_delete(client_state: *mut LlmpClient) {
    let mut i: c_ulong = 0;
    while i < (*client_state).out_map_count {
        afl_shmem_deinit(&mut *(*client_state).out_maps.offset(i as isize));
        i = i.wrapping_add(1)
    }
    afl_free((*client_state).out_maps as *mut c_void);
    (*client_state).out_maps = 0 as *mut AflShmem;
    (*client_state).out_map_count = 0 as c_ulong;
    afl_free((*client_state).new_out_page_hooks as *mut c_void);
    (*client_state).new_out_page_hooks = 0 as *mut LlmpHookdataGeneric;
    (*client_state).new_out_page_hook_count = 0 as c_ulong;
    afl_shmem_deinit((*client_state).current_broadcast_map);
    free((*client_state).current_broadcast_map as *mut c_void);
    (*client_state).current_broadcast_map = 0 as *mut AflShmem;
    free(client_state as *mut c_void);
}

impl Drop for LlmpClient {
    fn drop(&mut self) {
        unsafe { llmp_client_delete(self) };
    }
}

/// Adds a hook that gets called in the client for each new outgoing page the client creates.
pub unsafe fn llmp_client_add_new_out_page_hook(
    client: *mut LlmpClient,
    hook: Option<LlmpClientNewPageHookFn>,
    data: *mut c_void,
) -> AflRet {
    return llmp_add_hook_generic(
        &mut (*client).new_out_page_hooks,
        &mut (*client).new_out_page_hook_count,
        ::std::mem::transmute::<Option<LlmpClientNewPageHookFn>, *mut c_void>(hook),
        data,
    );
}

/// Clean up the broker instance
unsafe fn llmp_broker_deinit(broker: *mut LlmpBroker) {
    let mut i: c_ulong;
    i = 0 as c_ulong;
    while i < (*broker).broadcast_map_count {
        afl_shmem_deinit(&mut *(*broker).broadcast_maps.offset(i as isize));
        i = i.wrapping_add(1)
    }
    i = 0 as c_ulong;
    while i < (*broker).llmp_client_count {
        afl_shmem_deinit((*(*broker).llmp_clients.offset(i as isize)).cur_client_map);
        free((*(*broker).llmp_clients.offset(i as isize)).cur_client_map as *mut c_void);
        i = i.wrapping_add(1)
        // TODO: Properly clean up the client
    }
    afl_free((*broker).broadcast_maps as *mut c_void);
    (*broker).broadcast_map_count = 0 as c_ulong;
    afl_free((*broker).llmp_clients as *mut c_void);
    (*broker).llmp_client_count = 0 as c_ulong;
}

impl Drop for LlmpBroker {
    fn drop(&mut self) {
        unsafe { llmp_broker_deinit(self) };
    }
}
