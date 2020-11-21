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

use core::sync::atomic::{compiler_fence, Ordering};
use libc::{c_int, c_uint, c_ulong, c_ushort, c_void};
use std::process::exit;
use std::str;

use crate::utils::next_pow2;

use super::shmem_translated::{afl_shmem_deinit, afl_shmem_init, afl_shmem_by_str, afl_shmem};

extern "C" {
    #[no_mangle]
    fn usleep(__useconds: c_uint) -> c_int;
    #[no_mangle]
    fn fork() -> c_int;
    #[no_mangle]
    fn calloc(_: c_ulong, _: c_ulong) -> *mut c_void;
    #[no_mangle]
    fn realloc(_: *mut c_void, _: c_ulong) -> *mut c_void;
    #[no_mangle]
    fn free(__ptr: *mut c_void);
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

/* AFL alloc buffer, the struct is here so we don't need to do fancy ptr
 * arithmetics */
#[derive(Copy, Clone)]
#[repr(C)]
pub struct afl_alloc_buf {
    pub complete_size: c_ulong,
    pub magic: c_ulong,
    pub buf: [u8; 0],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_client {
    pub id: u32,
    pub last_msg_recvd: *mut llmp_message,
    pub current_broadcast_map: *mut afl_shmem,
    pub last_msg_sent: *mut llmp_message,
    pub out_map_count: c_ulong,
    pub out_maps: *mut afl_shmem,
    pub new_out_page_hook_count: c_ulong,
    pub new_out_page_hooks: *mut llmp_hookdata_generic,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_hookdata_generic {
    pub func: *mut c_void,
    pub data: *mut c_void,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct llmp_message {
    pub tag: c_uint,
    pub sender: c_uint,
    pub message_id: c_uint,
    pub buf_len: c_ulong,
    pub buf_len_padded: c_ulong,
    pub buf: [u8; 0],
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_broker_state {
    pub last_msg_sent: *mut llmp_message,
    pub broadcast_map_count: c_ulong,
    pub broadcast_maps: *mut afl_shmem,
    pub msg_hook_count: c_ulong,
    pub msg_hooks: *mut llmp_hookdata_generic,
    pub llmp_client_count: c_ulong,
    pub llmp_clients: *mut llmp_broker_client_metadata,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct llmp_broker_client_metadata {
    pub client_type: LlmpClientType,
    pub client_state: *mut llmp_client,
    pub cur_client_map: *mut afl_shmem,
    pub last_msg_broker_read: *mut llmp_message,
    pub pid: c_int,
    pub clientloop: LlmpClientloopFunc,
    pub data: *mut c_void,
}

pub type LlmpClientloopFunc =
    Option<unsafe extern "C" fn(_: *mut llmp_client, _: *mut c_void) -> ()>;
pub type LlmpClientType = c_uint;
pub const LLMP_CLIENT_TYPE_FOREIGN_PROCESS: LlmpClientType = 3;
pub const LLMP_CLIENT_TYPE_CHILD_PROCESS: LlmpClientType = 2;

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct llmp_page {
    pub sender: u32,
    pub save_to_unmap: c_ushort,
    pub sender_dead: c_ushort,
    pub current_msg_id: c_ulong,
    pub c_ulongotal: c_ulong,
    pub size_used: c_ulong,
    pub max_alloc_size: c_ulong,
    pub messages: [llmp_message; 0],
}

pub type LlmpMessageHookFn = unsafe extern "C" fn(
    _: *mut llmp_broker_state,
    _: *mut llmp_broker_client_metadata,
    _: *mut llmp_message,
    _: *mut c_void,
) -> bool;
pub type LlmpClientNewPageHookFn =
    unsafe extern "C" fn(_: *mut llmp_client, _: *mut llmp_page, _: *mut c_void) -> ();
/* Just a random msg */
/* Message payload when a client got added LLMP_TAG_CLIENT_ADDED_V1 */
/* A new sharedmap appeared.
This is an internal message!
LLMP_TAG_NEW_PAGE_V1
*/

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct llmp_payload_new_page {
    pub map_size: c_ulong,
    pub shm_str: [u8; 20],
}

/* Returs the container element to this ptr */
#[inline]
unsafe extern "C" fn afl_alloc_bufptr(buf: *mut c_void) -> *mut afl_alloc_buf {
    return (buf as *mut u8).offset(-(16 as c_ulong as isize)) as *mut afl_alloc_buf;
}
/* This function makes sure *size is > size_needed after call.
It will realloc *buf otherwise.
*size will grow exponentially as per:
https://blog.mozilla.org/nnethercote/2014/11/04/please-grow-your-buffers-exponentially/
Will return NULL and free *buf if size_needed is <1 or realloc failed.
@return For convenience, this function returns *buf.
*/
#[inline]
unsafe extern "C" fn afl_realloc(buf: *mut c_void, mut size_needed: c_ulong) -> *mut c_void {
    let mut new_buf: *mut afl_alloc_buf = 0 as *mut afl_alloc_buf;
    let mut current_size: c_ulong = 0 as c_int as c_ulong;
    let mut next_size: c_ulong;
    if !buf.is_null() {
        /* the size is always stored at buf - 1*c_ulong */
        new_buf = afl_alloc_bufptr(buf);
        if (*new_buf).magic != 0xaf1a110c as c_uint as c_ulong {
            panic!(format!(
                "Illegal, non-null pointer passed to afl_realloc (buf {:?}, magic {:?})",
                new_buf,
                (*new_buf).magic as c_uint
            ));
        }
        current_size = (*new_buf).complete_size
    }
    size_needed = (size_needed as c_ulong).wrapping_add(16 as c_ulong) as c_ulong;
    /* No need to realloc */
    if current_size >= size_needed {
        return buf;
    }
    /* No initial size was set */
    if size_needed < 64 as c_int as c_ulong {
        next_size = 64 as c_int as c_ulong
    } else {
        /* grow exponentially */
        next_size = next_pow2(size_needed);
        /* handle overflow: fall back to the original size_needed */
        if next_size == 0 {
            next_size = size_needed
        }
    }
    /* alloc */
    new_buf = realloc(new_buf as *mut c_void, next_size) as *mut afl_alloc_buf;
    if new_buf.is_null() {
        return 0 as *mut c_void;
    }
    (*new_buf).complete_size = next_size;
    (*new_buf).magic = 0xaf1a110c as c_uint as c_ulong;
    return (*new_buf).buf.as_mut_ptr() as *mut c_void;
}
#[inline]
unsafe extern "C" fn afl_free(buf: *mut c_void) {
    if !buf.is_null() {
        free(afl_alloc_bufptr(buf) as *mut c_void);
    };
}
#[inline]
unsafe extern "C" fn shmem2page(afl_shmem: *mut afl_shmem) -> *mut llmp_page {
    return (*afl_shmem).map as *mut llmp_page;
}
/* If a msg is contained in the current page */
#[no_mangle]
pub unsafe extern "C" fn llmp_msg_in_page(page: *mut llmp_page, msg: *mut llmp_message) -> bool {
    /* DBG("llmp_msg_in_page %p within %p-%p\n", msg, page, page + page->c_ulongotal); */
    return (page as *mut u8) < msg as *mut u8
        && (page as *mut u8).offset((*page).c_ulongotal as isize) > msg as *mut u8;
}
/* allign to LLMP_ALIGNNMENT bytes */
#[inline]
unsafe extern "C" fn llmp_align(to_align: c_ulong) -> c_ulong {
    if 64 as c_int == 0 as c_int
        || to_align.wrapping_rem(64 as c_int as c_ulong) == 0 as c_int as c_ulong
    {
        return to_align;
    }
    return to_align.wrapping_add(
        (64 as c_int as c_ulong).wrapping_sub(to_align.wrapping_rem(64 as c_int as c_ulong)),
    );
}
/* In case we don't have enough space, make sure the next page will be large
enough. For now, we want to have at least enough space to store 2 of the
largest messages we encountered. */
#[inline]
unsafe extern "C" fn new_map_size(max_alloc: c_ulong) -> c_ulong {
    return next_pow2({
        let mut _a: c_ulong =
            max_alloc
                .wrapping_mul(2 as c_int as c_ulong)
                .wrapping_add(llmp_align(
                    (::std::mem::size_of::<llmp_message>() as c_ulong)
                        .wrapping_add(::std::mem::size_of::<llmp_payload_new_page>() as c_ulong),
                ));
        let mut _b: c_ulong = ((1 as c_int) << 28 as c_int) as c_ulong;
        if _a > _b {
            _a
        } else {
            _b
        }
    });
}
/* Initialize a new llmp_page. size should be relative to
 * llmp_page->messages */
unsafe extern "C" fn _llmp_page_init(mut page: *mut llmp_page, sender: u32, size: c_ulong) {
    (*page).sender = sender;
    ::std::ptr::write_volatile(
        &mut (*page).current_msg_id as *mut c_ulong,
        0 as c_int as c_ulong,
    );
    (*page).max_alloc_size = 0 as c_int as c_ulong;
    (*page).c_ulongotal = size;
    (*page).size_used = 0 as c_int as c_ulong;
    (*(*page).messages.as_mut_ptr()).message_id = 0 as c_uint;
    (*(*page).messages.as_mut_ptr()).tag = 0xdeadaf as c_uint;
    ::std::ptr::write_volatile(&mut (*page).save_to_unmap as *mut u16, 0 as c_int as u16);
    ::std::ptr::write_volatile(&mut (*page).sender_dead as *mut u16, 0 as c_int as u16);
}
/* Pointer to the message behind the last message */
#[inline]
unsafe extern "C" fn _llmp_next_msg_ptr(last_msg: *mut llmp_message) -> *mut llmp_message {
    /* DBG("_llmp_next_msg_ptr %p %lu + %lu\n", last_msg, last_msg->buf_len_padded, sizeof(llmp_message)); */
    return (last_msg as *mut u8)
        .offset(::std::mem::size_of::<llmp_message>() as c_ulong as isize)
        .offset((*last_msg).buf_len_padded as isize) as *mut llmp_message;
}
/* Read next message. */
#[no_mangle]
pub unsafe extern "C" fn llmp_recv(
    page: *mut llmp_page,
    last_msg: *mut llmp_message,
) -> *mut llmp_message {
    /* DBG("llmp_recv %p %p\n", page, last_msg); */
    compiler_fence(Ordering::SeqCst);
    if (*page).current_msg_id == 0 {
        /* No messages yet */
        return 0 as *mut llmp_message;
    } else if last_msg.is_null() {
        /* We never read a message from this queue. Return first. */
        return (*page).messages.as_mut_ptr();
    } else if (*last_msg).message_id as c_ulong == (*page).current_msg_id {
        /* Oops! No new message! */
        return 0 as *mut llmp_message;
    } else {
        return _llmp_next_msg_ptr(last_msg);
    };
}
/* Blocks/spins until the next message gets posted to the page,
then returns that message. */
#[no_mangle]
pub unsafe extern "C" fn llmp_recv_blocking(
    page: *mut llmp_page,
    last_msg: *mut llmp_message,
) -> *mut llmp_message {
    let mut current_msg_id: u32 = 0 as c_int as u32;
    if !last_msg.is_null() {
        if (*last_msg).tag == 0xaf1e0f1 as c_int as c_uint
            && llmp_msg_in_page(page, last_msg) as c_int != 0
        {
            panic!("BUG: full page passed to await_message_blocking or reset failed");
        }
        current_msg_id = (*last_msg).message_id
    }
    loop {
        compiler_fence(Ordering::SeqCst);
        if (*page).current_msg_id != current_msg_id as c_ulong {
            let ret: *mut llmp_message = llmp_recv(page, last_msg);
            if ret.is_null() {
                panic!("BUG: blocking llmp message should never be NULL");
            }
            return ret;
        }
    }
}
/* Special allocation function for EOP messages (and nothing else!)
  The normal alloc will fail if there is not enough space for buf_len_padded + EOP
  So if llmp_alloc_next fails, create new page if necessary, use this function,
  place EOP, commit EOP, reset, alloc again on the new space.
*/
#[no_mangle]
pub unsafe extern "C" fn llmp_alloc_eop(
    mut page: *mut llmp_page,
    mut last_msg: *mut llmp_message,
) -> *mut llmp_message {
    if (*page).size_used.wrapping_add(llmp_align(
        (::std::mem::size_of::<llmp_message>() as c_ulong)
            .wrapping_add(::std::mem::size_of::<llmp_payload_new_page>() as c_ulong),
    )) > (*page).c_ulongotal
    {
        panic!(format!("PROGRAM ABORT : BUG: EOP does not fit in page! page {:?}, size_current {:?}, c_ulongotal {:?}", page,
               (*page).size_used, (*page).c_ulongotal));
    }
    let mut ret: *mut llmp_message = if !last_msg.is_null() {
        _llmp_next_msg_ptr(last_msg)
    } else {
        (*page).messages.as_mut_ptr()
    };
    if (*ret).tag == 0xa143af11 as c_uint {
        panic!("Did not call send() on last message!");
    }
    (*ret).buf_len_padded = ::std::mem::size_of::<llmp_payload_new_page>() as c_ulong;
    (*ret).message_id = if !last_msg.is_null() {
        (*last_msg).message_id =
            ((*last_msg).message_id as c_uint).wrapping_add(1 as c_int as c_uint) as u32 as u32;
        (*last_msg).message_id
    } else {
        1 as c_uint
    };
    (*ret).tag = 0xaf1e0f1 as c_int as u32;
    (*page).size_used = ((*page).size_used as c_ulong).wrapping_add(llmp_align(
        (::std::mem::size_of::<llmp_message>() as c_ulong)
            .wrapping_add(::std::mem::size_of::<llmp_payload_new_page>() as c_ulong),
    )) as c_ulong;
    return ret;
}
/* Will return a ptr to the next msg buf, or NULL if map is full.
Never call alloc_next without either sending or cancelling the last allocated message for this page!
There can only ever be up to one message allocated per page at each given time.
*/
#[no_mangle]
pub unsafe extern "C" fn llmp_alloc_next(
    mut page: *mut llmp_page,
    last_msg: *mut llmp_message,
    buf_len: c_ulong,
) -> *mut llmp_message {
    let mut buf_len_padded: c_ulong = buf_len;
    let mut complete_msg_size: c_ulong =
        llmp_align((::std::mem::size_of::<llmp_message>() as c_ulong).wrapping_add(buf_len_padded));
    /* DBG("XXX complete_msg_size %lu (h: %lu)\n", complete_msg_size, sizeof(llmp_message)); */
    /* In case we don't have enough space, make sure the next page will be large
     * enough */
    (*page).max_alloc_size = {
        let mut _a: c_ulong = (*page).max_alloc_size;
        let mut _b: c_ulong = complete_msg_size;
        if _a > _b {
            _a
        } else {
            _b
        }
    };
    let mut ret: *mut llmp_message;
    /* DBG("last_msg %p %d (%d)\n", last_msg, last_msg ? (int)last_msg->tag : -1, (int)LLMP_TAG_END_OF_PAGE_V1); */
    if last_msg.is_null() || (*last_msg).tag == 0xaf1e0f1 as c_int as c_uint {
        /* We start fresh */
        ret = (*page).messages.as_mut_ptr();
        /* The initial message may not be alligned, so we at least align the end of
        it. Technically, c_ulong can be smaller than a pointer, then who knows what
        happens */
        let base_addr: c_ulong = ret as c_ulong;
        buf_len_padded = llmp_align(base_addr.wrapping_add(complete_msg_size))
            .wrapping_sub(base_addr)
            .wrapping_sub(::std::mem::size_of::<llmp_message>() as c_ulong);
        complete_msg_size =
            buf_len_padded.wrapping_add(::std::mem::size_of::<llmp_message>() as c_ulong);
        /* DBG("XXX complete_msg_size NEW %lu\n", complete_msg_size); */
        /* Still space for the new message plus the additional "we're full" message?
         */
        if (*page)
            .size_used
            .wrapping_add(complete_msg_size)
            .wrapping_add(llmp_align(
                (::std::mem::size_of::<llmp_message>() as c_ulong)
                    .wrapping_add(::std::mem::size_of::<llmp_payload_new_page>() as c_ulong),
            ))
            > (*page).c_ulongotal
        {
            /* We're full. */
            return 0 as *mut llmp_message;
        }
        /* We need to start with 1 for ids, as current message id is initialized
         * with 0... */
        (*ret).message_id = if !last_msg.is_null() {
            (*last_msg).message_id.wrapping_add(1 as c_int as c_uint)
        } else {
            1 as c_int as c_uint
        }
    } else if (*page).current_msg_id != (*last_msg).message_id as c_ulong {
        /* Oops, wrong usage! */
        panic!(format!("BUG: The current message never got commited using llmp_send! (page->current_msg_id {:?}, last_msg->message_id: {})", (*page).current_msg_id, (*last_msg).message_id));
    } else {
        buf_len_padded =
            complete_msg_size.wrapping_sub(::std::mem::size_of::<llmp_message>() as c_ulong);
        /* DBG("XXX ret %p id %u buf_len_padded %lu complete_msg_size %lu\n", ret, ret->message_id, buf_len_padded,
         * complete_msg_size); */
        if (*page)
            .size_used
            .wrapping_add(complete_msg_size)
            .wrapping_add(llmp_align(
                (::std::mem::size_of::<llmp_message>() as c_ulong)
                    .wrapping_add(::std::mem::size_of::<llmp_payload_new_page>() as c_ulong),
            ))
            > (*page).c_ulongotal
        {
            /* Still space for the new message plus the additional "we're full" message?
             */
            /* We're full. */
            return 0 as *mut llmp_message;
        }
        ret = _llmp_next_msg_ptr(last_msg);
        (*ret).message_id = (*last_msg).message_id.wrapping_add(1 as c_int as c_uint)
    }
    /* The beginning of our message should be messages + size_used, else nobody
     * sent the last msg! */
    /* DBG("XXX ret %p - page->messages %p = %lu != %lu, will add %lu -> %p\n", ret, page->messages,
       (c_ulong)((u8 *)ret - (u8 *)page->messages), page->size_used, complete_msg_size, ((u8 *)ret) + complete_msg_size);
    */
    if last_msg.is_null() && (*page).size_used != 0
        || ((ret as *mut u8).wrapping_sub((*page).messages.as_mut_ptr() as *mut u8 as usize))
            as c_ulong
            != (*page).size_used
    {
        panic!(format!("Allocated new message without calling send() inbetween. ret: {:?}, page: {:?}, complete_msg_size: {:?}, size_used: {:?}, last_msg: {:?}", ret, page,
               buf_len_padded, (*page).size_used, last_msg));
    }
    (*page).size_used = ((*page).size_used as c_ulong).wrapping_add(complete_msg_size) as c_ulong;
    (*ret).buf_len_padded = buf_len_padded;
    (*ret).buf_len = buf_len;
    /* DBG("Returning new message at %p with len %ld, TAG was %x", ret, ret->buf_len_padded, ret->tag); */
    /* Maybe catch some bugs... */
    (*_llmp_next_msg_ptr(ret)).tag = 0xdeadaf as c_uint;
    (*ret).tag = 0xa143af11 as c_uint;
    return ret;
}
/* Commit the message last allocated by llmp_alloc_next to the queue.
 After commiting, the msg shall no longer be altered!
 It will be read by the consuming threads (broker->clients or client->broker)
*/
#[no_mangle]
pub unsafe extern "C" fn llmp_send(page: *mut llmp_page, msg: *mut llmp_message) -> bool {
    if (*msg).tag == 0xdeadaf as c_uint {
        panic!(format!(
            "No tag set on message with id {}",
            (*msg).message_id
        ));
    }
    if msg.is_null() || !llmp_msg_in_page(page, msg) {
        return 0 as c_int != 0;
    }
    compiler_fence(Ordering::SeqCst);
    ::std::ptr::write_volatile(
        &mut (*page).current_msg_id as *mut c_ulong,
        (*msg).message_id as c_ulong,
    );

    compiler_fence(Ordering::SeqCst);
    return 1 as c_int != 0;
}
#[inline]
unsafe extern "C" fn _llmp_broker_current_broadcast_map(
    broker_state: *mut llmp_broker_state,
) -> *mut afl_shmem {
    return &mut *(*broker_state).broadcast_maps.offset(
        (*broker_state)
            .broadcast_map_count
            .wrapping_sub(1 as c_int as c_ulong) as isize,
    ) as *mut afl_shmem;
}
/* create a new shard page. Size_requested will be the min size, you may get a
 * larger map. Retruns NULL on error. */
#[no_mangle]
pub unsafe extern "C" fn llmp_new_page_shmem(
    uninited_afl_shmem: *mut afl_shmem,
    sender: c_ulong,
    size_requested: c_ulong,
) -> *mut llmp_page {
    let size: c_ulong = next_pow2({
        let mut _a: c_ulong = size_requested.wrapping_add(40 as c_ulong);
        let mut _b: c_ulong = ((1 as c_int) << 28 as c_int) as c_ulong;
        if _a > _b {
            _a
        } else {
            _b
        }
    });
    if afl_shmem_init(uninited_afl_shmem, size).is_null() {
        return 0 as *mut llmp_page;
    }
    _llmp_page_init(
        shmem2page(uninited_afl_shmem),
        sender as u32,
        size_requested,
    );
    return shmem2page(uninited_afl_shmem);
}
/* This function handles EOP by creating a new shared page and informing the
listener about it using a EOP message. */
unsafe extern "C" fn llmp_handle_out_eop(
    mut maps: *mut afl_shmem,
    map_count_p: *mut c_ulong,
    last_msg_p: *mut *mut llmp_message,
) -> *mut afl_shmem {
    let map_count: u32 = *map_count_p as u32;
    let mut old_map: *mut llmp_page =
        shmem2page(&mut *maps.offset(map_count.wrapping_sub(1 as c_int as c_uint) as isize));
    maps = afl_realloc(
        maps as *mut c_void,
        (map_count.wrapping_add(1 as c_int as c_uint) as c_ulong)
            .wrapping_mul(::std::mem::size_of::<afl_shmem>() as c_ulong),
    ) as *mut afl_shmem;
    if maps.is_null() {
        return 0 as *mut afl_shmem;
    }
    /* Broadcast a new, large enough, message. Also sorry for that c ptr stuff! */
    let mut new_map: *mut llmp_page = llmp_new_page_shmem(
        &mut *maps.offset(map_count as isize),
        (*old_map).sender as c_ulong,
        new_map_size((*old_map).max_alloc_size),
    );
    if new_map.is_null() {
        afl_free(maps as *mut c_void);
        return 0 as *mut afl_shmem;
    }
    /* Realloc may have changed the location of maps_p (and old_map) in memory :/
     */
    old_map = shmem2page(&mut *maps.offset(map_count.wrapping_sub(1 as c_int as c_uint) as isize));
    *map_count_p = map_count.wrapping_add(1 as c_int as c_uint) as c_ulong;
    ::std::ptr::write_volatile(
        &mut (*new_map).current_msg_id as *mut c_ulong,
        (*old_map).current_msg_id,
    );
    (*new_map).max_alloc_size = (*old_map).max_alloc_size;
    /* On the old map, place a last message linking to the new map for the clients
     * to consume */
    let mut out: *mut llmp_message = llmp_alloc_eop(old_map, *last_msg_p);
    (*out).sender = (*old_map).sender;
    let mut new_page_msg: *mut llmp_payload_new_page =
        (*out).buf.as_mut_ptr() as *mut llmp_payload_new_page;
    /* copy the infos to the message we're going to send on the old buf */
    (*new_page_msg).map_size = (*maps.offset(map_count as isize)).map_size;
    memcpy(
        (*new_page_msg).shm_str.as_mut_ptr() as *mut c_void,
        (*maps.offset(map_count as isize)).shm_str.as_mut_ptr() as *const c_void,
        20 as c_int as c_ulong,
    );
    // We never sent a msg on the new buf */
    *last_msg_p = 0 as *mut llmp_message;
    /* Send the last msg on the old buf */
    if !llmp_send(old_map, out) {
        afl_free(maps as *mut c_void);
        return 0 as *mut afl_shmem;
    }
    return maps;
}
/* no more space left! We'll have to start a new page */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_handle_out_eop(mut broker: *mut llmp_broker_state) -> AflRet {
    (*broker).broadcast_maps = llmp_handle_out_eop(
        (*broker).broadcast_maps,
        &mut (*broker).broadcast_map_count,
        &mut (*broker).last_msg_sent,
    );
    return if !(*broker).broadcast_maps.is_null() {
        AFL_RET_SUCCESS
    } else {
        AFL_RET_ALLOC
    } as AflRet;
}
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_alloc_next(
    broker: *mut llmp_broker_state,
    len: c_ulong,
) -> *mut llmp_message {
    let mut broadcast_page: *mut llmp_page = shmem2page(_llmp_broker_current_broadcast_map(broker));
    let mut out: *mut llmp_message = llmp_alloc_next(broadcast_page, (*broker).last_msg_sent, len);
    if out.is_null() {
        /* no more space left! We'll have to start a new page */
        let ret: AflRet = llmp_broker_handle_out_eop(broker);
        if ret != AFL_RET_SUCCESS as AflRet {
            panic!("Error handling broker out EOP");
        }
        /* llmp_handle_out_eop allocates a new current broadcast_map */
        broadcast_page = shmem2page(_llmp_broker_current_broadcast_map(broker));
        /* the alloc is now on a new page */
        out = llmp_alloc_next(broadcast_page, (*broker).last_msg_sent, len);
        if out.is_null() {
            panic!(format!(
                "Error allocating {} bytes in shmap {:?}",
                len,
                (*_llmp_broker_current_broadcast_map(broker))
                    .shm_str
                    .as_mut_ptr(),
            ));
        }
    }
    return out;
}
/* Registers a new client for the given sharedmap str and size.
Be careful: Intenral realloc may change the location of the client map */
unsafe fn llmp_broker_register_client(
    mut broker: *mut llmp_broker_state,
    shm_str: &str,
    map_size: c_ulong,
) -> *mut llmp_broker_client_metadata {
    /* make space for a new client and calculate its id */
    (*broker).llmp_clients = afl_realloc(
        (*broker).llmp_clients as *mut c_void,
        (*broker)
            .llmp_client_count
            .wrapping_add(1 as c_int as c_ulong)
            .wrapping_mul(::std::mem::size_of::<llmp_broker_client_metadata>() as c_ulong),
    ) as *mut llmp_broker_client_metadata;
    if (*broker).llmp_clients.is_null() {
        return 0 as *mut llmp_broker_client_metadata;
    }
    let mut client: *mut llmp_broker_client_metadata = &mut *(*broker)
        .llmp_clients
        .offset((*broker).llmp_client_count as isize)
        as *mut llmp_broker_client_metadata;
    memset(
        client as *mut c_void,
        0 as c_int,
        ::std::mem::size_of::<llmp_broker_client_metadata>() as c_ulong,
    );
    (*client).client_state = calloc(
        1 as c_int as c_ulong,
        ::std::mem::size_of::<llmp_client>() as c_ulong,
    ) as *mut llmp_client;
    if (*client).client_state.is_null() {
        return 0 as *mut llmp_broker_client_metadata;
    }
    (*(*client).client_state).id = (*broker).llmp_client_count as u32;
    (*client).cur_client_map = calloc(
        1 as c_int as c_ulong,
        ::std::mem::size_of::<afl_shmem>() as c_ulong,
    ) as *mut afl_shmem;
    if (*client).cur_client_map.is_null() {
        return 0 as *mut llmp_broker_client_metadata;
    }
    if afl_shmem_by_str((*client).cur_client_map, shm_str, map_size).is_null() {
        return 0 as *mut llmp_broker_client_metadata;
    }
    (*broker).llmp_client_count = (*broker).llmp_client_count.wrapping_add(1);
    // tODO: Add client map
    return client;
}
/* broker broadcast to its own page for all others to read */
#[inline]
unsafe fn llmp_broker_handle_new_msgs(
    mut broker: *mut llmp_broker_state,
    mut client: *mut llmp_broker_client_metadata,
) {
    // TODO: We could memcpy a range of pending messages, instead of one by one.
    /* DBG("llmp_broker_handle_new_msgs %p %p->%u\n", broker, client, client->client_state->id); */
    let incoming: *mut llmp_page = shmem2page((*client).cur_client_map);
    let mut current_message_id: u32 = if !(*client).last_msg_broker_read.is_null() {
        (*(*client).last_msg_broker_read).message_id
    } else {
        0 as c_int as c_uint
    };
    while current_message_id as c_ulong != (*incoming).current_msg_id {
        let msg: *mut llmp_message = llmp_recv(incoming, (*client).last_msg_broker_read);
        if msg.is_null() {
            panic!("No message received but not all message ids receved! Data out of sync?");
        }
        if (*msg).tag == 0xaf1e0f1 as c_int as c_uint {
            let pageinfo: *mut llmp_payload_new_page = {
                let mut _msg: *mut llmp_message = msg;
                (if (*_msg).buf_len >= ::std::mem::size_of::<llmp_payload_new_page>() as c_ulong {
                    (*_msg).buf.as_mut_ptr()
                } else {
                    0 as *mut u8
                }) as *mut llmp_payload_new_page
            };
            if pageinfo.is_null() {
                panic!(format!(
                    "Illegal message length for EOP (is {}, expected {})",
                    (*msg).buf_len_padded,
                    ::std::mem::size_of::<llmp_payload_new_page>() as c_ulong
                ));
            }
            /* We can reuse the map mem space, no need to free and calloc.
            However, the pageinfo points to the map we're about to unmap.
            Copy the contents first. */
            let mut pageinfo_cpy: llmp_payload_new_page = llmp_payload_new_page {
                map_size: 0,
                shm_str: [0; 20],
            };
            memcpy(
                &mut pageinfo_cpy as *mut llmp_payload_new_page as *mut c_void,
                pageinfo as *const c_void,
                ::std::mem::size_of::<llmp_payload_new_page>() as c_ulong,
            );
            let client_map: *mut afl_shmem = (*client).cur_client_map;
            ::std::ptr::write_volatile(
                &mut (*shmem2page(client_map)).save_to_unmap as *mut u16,
                1 as c_int as u16,
            );
            afl_shmem_deinit(client_map);
            if afl_shmem_by_str(
                client_map,
                str::from_utf8(&(*pageinfo).shm_str).unwrap(),
                (*pageinfo).map_size,
            )
            .is_null()
            {
                panic!(format!(
                    "Could not get shmem by str for map {:?} of size {:?}",
                    (*pageinfo).shm_str.as_mut_ptr(),
                    (*pageinfo).map_size
                ));
            }
        } else if (*msg).tag == 0xc11e471 as c_int as c_uint {
            /* This client informs us about yet another new client
            add it to the list! Also, no need to forward this msg. */
            let pageinfo: *mut llmp_payload_new_page = {
                let mut _msg: *mut llmp_message = msg;
                (if (*_msg).buf_len >= ::std::mem::size_of::<llmp_payload_new_page>() as c_ulong {
                    (*_msg).buf.as_mut_ptr()
                } else {
                    0 as *mut u8
                }) as *mut llmp_payload_new_page
            };
            if pageinfo.is_null() {
                println!("Ignoring broken CLIENT_ADDED msg due to incorrect size. Expected {:?} but got {:?}",
                       ::std::mem::size_of::<llmp_payload_new_page>() as
                           c_ulong, (*msg).buf_len_padded);
            }
            /* register_client may realloc the clients, we need to find ours again */
            let client_id: u32 = (*(*client).client_state).id;
            if llmp_broker_register_client(
                broker,
                str::from_utf8(&(*pageinfo).shm_str).unwrap(),
                (*pageinfo).map_size,
            )
            .is_null()
            {
                panic!(format!(
                    "Could not register clientprocess with shm_str {:?}",
                    (*pageinfo).shm_str.as_mut_ptr()
                ));
            }
            (*client).client_type = LLMP_CLIENT_TYPE_FOREIGN_PROCESS;
            /* find client again */
            client = &mut *(*broker).llmp_clients.offset(client_id as isize)
                as *mut llmp_broker_client_metadata
        } else {
            let mut forward_msg: bool = 1 as c_int != 0;
            let mut i: c_ulong = 0;
            while i < (*broker).msg_hook_count {
                let msg_hook: *mut llmp_hookdata_generic =
                    &mut *(*broker).msg_hooks.offset(i as isize) as *mut llmp_hookdata_generic;
                forward_msg = forward_msg as c_int != 0
                    && ::std::mem::transmute::<*mut c_void, Option<LlmpMessageHookFn>>(
                        (*msg_hook).func,
                    )
                    .expect("non-null function pointer")(
                        broker, client, msg, (*msg_hook).data
                    ) as c_int
                        != 0;
                if !llmp_msg_in_page(shmem2page((*client).cur_client_map), msg) {
                    /* Special handling in case the client got exchanged inside the message_hook, for example after a crash. */
                    return;
                }
                i = i.wrapping_add(1)
            }
            if forward_msg {
                let mut out: *mut llmp_message =
                    llmp_broker_alloc_next(broker, (*msg).buf_len_padded);
                if out.is_null() {
                    panic!(format!(
                        "Error allocating {} bytes in shmap {:?}",
                        (*msg).buf_len_padded,
                        (*_llmp_broker_current_broadcast_map(broker))
                            .shm_str
                            .as_mut_ptr(),
                    ));
                }
                /* Copy over the whole message.
                If we should need zero copy, we could instead post a link to the
                original msg with the map_id and offset. */
                let actual_size: c_ulong = (*out).buf_len_padded;
                memcpy(
                    out as *mut c_void,
                    msg as *const c_void,
                    (::std::mem::size_of::<llmp_message>() as c_ulong)
                        .wrapping_add((*msg).buf_len_padded),
                );
                (*out).buf_len_padded = actual_size;
                /* We need to replace the message ID with our own */
                let out_page: *mut llmp_page =
                    shmem2page(_llmp_broker_current_broadcast_map(broker));
                (*out).message_id = (*out_page)
                    .current_msg_id
                    .wrapping_add(1 as c_int as c_ulong) as u32;
                if !llmp_send(out_page, out) {
                    panic!("Error sending msg");
                }
                (*broker).last_msg_sent = out
            }
        }
        (*client).last_msg_broker_read = msg;
        current_message_id = (*msg).message_id
    }
}
/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page, once. */
/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page, once. */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_once(broker: *mut llmp_broker_state) {
    compiler_fence(Ordering::SeqCst);
    let mut i: u32 = 0;
    while (i as c_ulong) < (*broker).llmp_client_count {
        let client: *mut llmp_broker_client_metadata =
            &mut *(*broker).llmp_clients.offset(i as isize) as *mut llmp_broker_client_metadata;
        llmp_broker_handle_new_msgs(broker, client);
        i = i.wrapping_add(1)
    }
}
/* The broker walks all pages and looks for changes, then broadcasts them on
 * its own shared page */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_loop(broker: *mut llmp_broker_state) {
    loop {
        compiler_fence(Ordering::SeqCst);
        llmp_broker_once(broker);
        /* 5 milis of sleep for now to not busywait at 100% */
        usleep((5 as c_int * 1000 as c_int) as c_uint);
    }
}
/* A new page will be used. Notify each registered hook in the client about this fact. */
unsafe extern "C" fn llmp_clientrigger_new_out_page_hooks(client: *mut llmp_client) {
    let mut i: c_ulong = 0;
    while i < (*client).new_out_page_hook_count {
        ::std::mem::transmute::<*mut c_void, Option<LlmpClientNewPageHookFn>>(
            (*(*client).new_out_page_hooks.offset(i as isize)).func,
        )
        .expect("non-null function pointer")(
            client,
            shmem2page(
                &mut *(*client)
                    .out_maps
                    .offset((*client).out_map_count.wrapping_sub(1 as c_int as c_ulong) as isize),
            ),
            (*(*client).new_out_page_hooks.offset(i as isize)).data,
        );
        i = i.wrapping_add(1)
    }
}
/* A wrapper around unpacking the data, calling through to the loop */
unsafe extern "C" fn _llmp_client_wrapped_loop(
    llmp_client_broker_metadata_ptr: *mut c_void,
) -> *mut c_void {
    let metadata: *mut llmp_broker_client_metadata =
        llmp_client_broker_metadata_ptr as *mut llmp_broker_client_metadata;
    /* Before doing anything else:, notify registered hooks about the new page we're about to use */
    llmp_clientrigger_new_out_page_hooks((*metadata).client_state);

    (*metadata).clientloop.expect("non-null function pointer")(
        (*metadata).client_state,
        (*metadata).data,
    );
    println!(
        "Client loop exited for client {}",
        (*(*metadata).client_state).id
    );
    return 0 as *mut c_void;
}
/* launch a specific client. This function is rarely needed - all registered clients will get launched at broker_run */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_launch_client(
    broker: *mut llmp_broker_state,
    mut clientdata: *mut llmp_broker_client_metadata,
) -> bool {
    if clientdata < (*broker).llmp_clients
        || clientdata
            > &mut *(*broker).llmp_clients.offset(
                (*broker)
                    .llmp_client_count
                    .wrapping_sub(1 as c_int as c_ulong) as isize,
            ) as *mut llmp_broker_client_metadata
    {
        println!(
            "[!] WARNING: Illegal client specified at ptr {:?} (instead of {:?} to {:?})",
            clientdata,
            (*broker).llmp_clients,
            &mut *(*broker).llmp_clients.offset(
                (*broker)
                    .llmp_client_count
                    .wrapping_sub(1 as c_int as c_ulong) as isize,
            ) as *mut llmp_broker_client_metadata,
        );
        return 0 as c_int != 0;
    }
    if (*clientdata).client_type as c_uint == LLMP_CLIENT_TYPE_CHILD_PROCESS as c_int as c_uint {
        if (*clientdata).pid != 0 {
            println!("[!] WARNING: Tried to relaunch already running client. Set ->pid to 0 if this is what you want.");
            return 0 as c_int != 0;
        }
        let child_id: c_int = fork();
        if child_id < 0 as c_int {
            println!("[!] WARNING: Could not fork");
            return 0 as c_int != 0;
        } else {
            if child_id == 0 as c_int {
                /* child */
                /* in the child, start loop, exit afterwards. */
                _llmp_client_wrapped_loop(clientdata as *mut c_void);
                exit(1);
            }
        }
        /* parent */
        (*clientdata).pid = child_id;
        return 1 as c_int != 0;
    } else {
        println!("[!] WARNING: Tried to spawn llmp child with unknown thread type.");
        return 0 as c_int != 0;
    }
    //return 1 as c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_launch_clientloops(broker: *mut llmp_broker_state) -> bool {
    let mut i: c_ulong = 0;
    while i < (*broker).llmp_client_count {
        if (*(*broker).llmp_clients.offset(i as isize)).client_type as c_uint
            == LLMP_CLIENT_TYPE_CHILD_PROCESS as c_int as c_uint
        {
            if !llmp_broker_launch_client(broker, &mut *(*broker).llmp_clients.offset(i as isize)) {
                println!("[!] WARNING: Could not launch all clients");
                return 0 as c_int != 0;
            }
        }
        i = i.wrapping_add(1)
    }
    return 1 as c_int != 0;
}
/* The broker walks all pages and looks for changes, then broadcasts them on
its own shared page.
Never returns. */
/* Start all threads and the main broker.
Same as llmp_broker_launch_threaded clients();
Never returns. */
/* Start all threads and the main broker. Never returns. */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_run(broker: *mut llmp_broker_state) {
    llmp_broker_launch_clientloops(broker);
    llmp_broker_loop(broker);
}
/*
 For non zero-copy, we want to get rid of old pages with duplicate messages
 eventually. This function This funtion sees if we can unallocate older pages.
 The broker would have informed us by setting the save_to_unmap-flag.
*/
unsafe extern "C" fn llmp_client_prune_old_pages(mut client: *mut llmp_client) {
    let current_map: *mut u8 = (*(*client)
        .out_maps
        .offset((*client).out_map_count.wrapping_sub(1 as c_int as c_ulong) as isize))
    .map;
    /* look for pages that are save_to_unmap, then unmap them. */
    while (*(*client).out_maps.offset(0 as c_int as isize)).map != current_map
        && (*shmem2page(&mut *(*client).out_maps.offset(0 as c_int as isize))).save_to_unmap
            as c_int
            != 0
    {
        /* This page is save to unmap. The broker already reads or read it. */
        afl_shmem_deinit(&mut *(*client).out_maps.offset(0 as c_int as isize));
        /* We remove at the start, move the other pages back. */
        memmove(
            (*client).out_maps as *mut c_void,
            (*client).out_maps.offset(1 as c_int as isize) as *const c_void,
            (*client)
                .out_map_count
                .wrapping_sub(1 as c_int as c_ulong)
                .wrapping_mul(::std::mem::size_of::<afl_shmem>() as c_ulong),
        );
        (*client).out_map_count = (*client).out_map_count.wrapping_sub(1)
    }
}
/* We don't have any space. Send eop, the reset to beginning of ringbuf */
unsafe extern "C" fn llmp_client_handle_out_eop(mut client: *mut llmp_client) -> bool {
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
    llmp_clientrigger_new_out_page_hooks(client);
    return 1 as c_int != 0;
}
/* A client receives a broadcast message. Returns null if no message is
 * availiable */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_recv(mut client: *mut llmp_client) -> *mut llmp_message {
    loop {
        let msg = llmp_recv(
            shmem2page((*client).current_broadcast_map),
            (*client).last_msg_recvd,
        );
        if msg.is_null() {
            return 0 as *mut llmp_message;
        }
        (*client).last_msg_recvd = msg;
        if (*msg).tag == 0xdeadaf as c_uint {
            panic!("BUG: Read unallocated msg");
        } else {
            if (*msg).tag == 0xaf1e0f1 as c_int as c_uint {
                /* we reached the end of the current page.
                We'll init a new page but can reuse the mem are of the current map.
                However, we cannot use the message if we deinit its page, so let's copy */
                let mut pageinfo_cpy: llmp_payload_new_page = llmp_payload_new_page {
                    map_size: 0,
                    shm_str: [0; 20],
                };
                let broadcast_map: *mut afl_shmem = (*client).current_broadcast_map;
                let pageinfo: *mut llmp_payload_new_page = {
                    let mut _msg: *mut llmp_message = msg;
                    (if (*_msg).buf_len >= ::std::mem::size_of::<llmp_payload_new_page>() as c_ulong
                    {
                        (*_msg).buf.as_mut_ptr()
                    } else {
                        0 as *mut u8
                    }) as *mut llmp_payload_new_page
                };
                if pageinfo.is_null() {
                    panic!(format!(
                        "Illegal message length for EOP (is {}, expected {})",
                        (*msg).buf_len_padded,
                        ::std::mem::size_of::<llmp_payload_new_page>() as c_ulong
                    ));
                }
                memcpy(
                    &mut pageinfo_cpy as *mut llmp_payload_new_page as *mut c_void,
                    pageinfo as *const c_void,
                    ::std::mem::size_of::<llmp_payload_new_page>() as c_ulong,
                );
                /* Never read by broker broker: shmem2page(map)->save_to_unmap = true; */
                afl_shmem_deinit(broadcast_map);
                if afl_shmem_by_str(
                    (*client).current_broadcast_map,
                    str::from_utf8(&(*pageinfo).shm_str).unwrap(),
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
/* A client blocks/spins until the next message gets posted to the page,
then returns that message. */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_recv_blocking(client: *mut llmp_client) -> *mut llmp_message {
    let mut page: *mut llmp_page = shmem2page((*client).current_broadcast_map);
    loop {
        compiler_fence(Ordering::SeqCst);
        /* busy-wait for a new msg_id to show up in the page */
        if (*page).current_msg_id
            != (if !(*client).last_msg_recvd.is_null() {
                (*(*client).last_msg_recvd).message_id
            } else {
                0 as c_int as c_uint
            }) as c_ulong
        {
            let ret: *mut llmp_message = llmp_client_recv(client);
            if !ret.is_null() {
                return ret;
            }
            /* last msg will exist, even if EOP was handled internally */
            page = shmem2page((*client).current_broadcast_map)
        }
    }
}
/* The current page could have changed in recv (EOP) */
/* Alloc the next message, internally handling end of page by allocating a new one. */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_alloc_next(
    client: *mut llmp_client,
    size: c_ulong,
) -> *mut llmp_message {
    if client.is_null() {
        panic!("Client is NULL");
    }
    let mut msg = llmp_alloc_next(
        shmem2page(
            &mut *(*client)
                .out_maps
                .offset((*client).out_map_count.wrapping_sub(1 as c_int as c_ulong) as isize),
        ),
        (*client).last_msg_sent,
        size,
    );
    if msg.is_null() {
        let last_map_count: c_ulong = (*client).out_map_count;
        /* Page is full -> Tell broker and start from the beginning.
        Also, pray the broker got all messaes we're overwriting. :) */
        if !llmp_client_handle_out_eop(client) {
            return 0 as *mut llmp_message;
        }
        if (*client).out_map_count == last_map_count
            || (*(*shmem2page(
                &mut *(*client)
                    .out_maps
                    .offset((*client).out_map_count.wrapping_sub(1 as c_int as c_ulong) as isize),
            ))
            .messages
            .as_mut_ptr())
            .tag != 0xdeadaf as c_uint
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
                    .offset((*client).out_map_count.wrapping_sub(1 as c_int as c_ulong) as isize),
            ),
            0 as *mut llmp_message,
            size,
        );
        if msg.is_null() {
            return 0 as *mut llmp_message;
        }
    }
    (*msg).sender = (*client).id;
    (*msg).message_id = if !(*client).last_msg_sent.is_null() {
        (*(*client).last_msg_sent).message_id.wrapping_add(1)
    } else {
        1 as c_int as c_uint
    };
    /* DBG("Allocated message at loc %p with buflen %ld", msg, msg->buf_len_padded); */
    return msg;
}
/* Cancel send of the next message, this allows us to allocate a new message without sending this one. */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_cancel(client: *mut llmp_client, mut msg: *mut llmp_message) {
    /* DBG("Client %d cancels send of msg at %p with tag 0x%X and size %ld", client->id, msg, msg->tag,
     * msg->buf_len_padded); */
    let mut page: *mut llmp_page = shmem2page(
        &mut *(*client)
            .out_maps
            .offset((*client).out_map_count.wrapping_sub(1 as c_int as c_ulong) as isize),
    );
    (*msg).tag = 0xdeadaf as c_uint;
    (*page).size_used = ((*page).size_used as c_ulong).wrapping_sub(
        (*msg)
            .buf_len_padded
            .wrapping_add(::std::mem::size_of::<llmp_message>() as c_ulong),
    ) as c_ulong;
}
/* Commits a msg to the client's out ringbuf */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_send(
    mut client_state: *mut llmp_client,
    msg: *mut llmp_message,
) -> bool {
    let page: *mut llmp_page = shmem2page(
        &mut *(*client_state).out_maps.offset(
            (*client_state)
                .out_map_count
                .wrapping_sub(1 as c_int as c_ulong) as isize,
        ),
    );
    let ret: bool = llmp_send(page, msg);
    (*client_state).last_msg_sent = msg;
    return ret;
}

/* Creates a new, unconnected, client state */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_new_unconnected() -> *mut llmp_client {
    let mut client_state: *mut llmp_client = calloc(
        1 as c_int as c_ulong,
        ::std::mem::size_of::<llmp_client>() as c_ulong,
    ) as *mut llmp_client;
    (*client_state).current_broadcast_map = calloc(
        1 as c_int as c_ulong,
        ::std::mem::size_of::<afl_shmem>() as c_ulong,
    ) as *mut afl_shmem;
    if (*client_state).current_broadcast_map.is_null() {
        return 0 as *mut llmp_client;
    }
    (*client_state).out_maps = afl_realloc(
        (*client_state).out_maps as *mut c_void,
        (1 as c_int as c_ulong).wrapping_mul(::std::mem::size_of::<afl_shmem>() as c_ulong),
    ) as *mut afl_shmem;
    if (*client_state).out_maps.is_null() {
        free((*client_state).current_broadcast_map as *mut c_void);
        free(client_state as *mut c_void);
        return 0 as *mut llmp_client;
    }
    (*client_state).out_map_count = 1 as c_int as c_ulong;
    if llmp_new_page_shmem(
        &mut *(*client_state).out_maps.offset(0 as c_int as isize),
        (*client_state).id as c_ulong,
        ((1 as c_int) << 28 as c_int) as c_ulong,
    )
    .is_null()
    {
        afl_free((*client_state).out_maps as *mut c_void);
        free((*client_state).current_broadcast_map as *mut c_void);
        free(client_state as *mut c_void);
        return 0 as *mut llmp_client;
    }
    (*client_state).new_out_page_hook_count = 0 as c_int as c_ulong;
    (*client_state).new_out_page_hooks = 0 as *mut llmp_hookdata_generic;
    return client_state;
}
/* Destroys the given cient state */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_delete(mut client_state: *mut llmp_client) {
    let mut i: c_ulong = 0;
    while i < (*client_state).out_map_count {
        afl_shmem_deinit(&mut *(*client_state).out_maps.offset(i as isize));
        i = i.wrapping_add(1)
    }
    afl_free((*client_state).out_maps as *mut c_void);
    (*client_state).out_maps = 0 as *mut afl_shmem;
    (*client_state).out_map_count = 0 as c_int as c_ulong;
    afl_free((*client_state).new_out_page_hooks as *mut c_void);
    (*client_state).new_out_page_hooks = 0 as *mut llmp_hookdata_generic;
    (*client_state).new_out_page_hook_count = 0 as c_int as c_ulong;
    afl_shmem_deinit((*client_state).current_broadcast_map);
    free((*client_state).current_broadcast_map as *mut c_void);
    (*client_state).current_broadcast_map = 0 as *mut afl_shmem;
    free(client_state as *mut c_void);
}

/* Register a new forked/child client.
Client thread will be called with llmp_client client, containing
the data in ->data. This will register a client to be spawned up as soon as
broker_loop() starts. Clients can also be added later via
llmp_broker_register_remote(..) or the local_tcp_client
*/
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_register_childprocess_clientloop(
    mut broker: *mut llmp_broker_state,
    clientloop: LlmpClientloopFunc,
    data: *mut c_void,
) -> bool {
    let mut client_map: afl_shmem = {
        let init = afl_shmem {
            shm_str: [0; 20],
            shm_id: 0,
            map: 0 as *mut u8,
            map_size: 0,
        };
        init
    };
    if llmp_new_page_shmem(
        &mut client_map,
        (*broker).llmp_client_count,
        ((1 as c_int) << 28 as c_int) as c_ulong,
    )
    .is_null()
    {
        return 0 as c_int != 0;
    }
    let mut client: *mut llmp_broker_client_metadata =
        llmp_broker_register_client(broker, str::from_utf8(&client_map.shm_str).unwrap(), client_map.map_size);
    if client.is_null() {
        afl_shmem_deinit(&mut client_map);
        return 0 as c_int != 0;
    }
    (*client).clientloop = clientloop;
    (*client).data = data;
    (*client).client_type = LLMP_CLIENT_TYPE_CHILD_PROCESS;
    /* Copy the already allocated shmem to the client state */
    (*(*client).client_state).out_maps = afl_realloc(
        (*(*client).client_state).out_maps as *mut c_void,
        ::std::mem::size_of::<afl_shmem>() as c_ulong,
    ) as *mut afl_shmem;
    if (*(*client).client_state).out_maps.is_null() {
        afl_shmem_deinit(&mut client_map);
        afl_shmem_deinit((*client).cur_client_map);
        /* "Unregister" by subtracting the client from count */
        (*broker).llmp_client_count = (*broker).llmp_client_count.wrapping_sub(1);
        return 0 as c_int != 0;
    }
    memcpy(
        (*(*client).client_state).out_maps as *mut c_void,
        &mut client_map as *mut afl_shmem as *const c_void,
        ::std::mem::size_of::<afl_shmem>() as c_ulong,
    );
    (*(*client).client_state).out_map_count = 1 as c_int as c_ulong;
    /* Each client starts with the very first map.
    They should then iterate through all maps once and work on all old messages.
    */
    (*(*client).client_state).current_broadcast_map =
        &mut *(*broker).broadcast_maps.offset(0 as c_int as isize) as *mut afl_shmem;
    (*(*client).client_state).out_map_count = 1 as c_int as c_ulong;
    return 1 as c_int != 0;
}

/* Generic function to add a hook to the mem pointed to by hooks_p, using afl_realloc on the mem area, and increasing
 * hooks_count_p */
#[no_mangle]
pub unsafe extern "C" fn llmp_add_hook_generic(
    hooks_p: *mut *mut llmp_hookdata_generic,
    hooks_count_p: *mut c_ulong,
    new_hook_func: *mut c_void,
    new_hook_data: *mut c_void,
) -> AflRet {
    let hooks_count: c_ulong = *hooks_count_p;
    let hooks: *mut llmp_hookdata_generic = afl_realloc(
        *hooks_p as *mut c_void,
        hooks_count
            .wrapping_add(1 as c_int as c_ulong)
            .wrapping_mul(::std::mem::size_of::<llmp_hookdata_generic>() as c_ulong),
    ) as *mut llmp_hookdata_generic;
    if hooks.is_null() {
        *hooks_p = 0 as *mut llmp_hookdata_generic;
        *hooks_count_p = 0 as c_int as c_ulong;
        return AFL_RET_ALLOC;
    }
    let ref mut fresh9 = (*hooks.offset(hooks_count as isize)).func;
    *fresh9 = new_hook_func;
    let ref mut fresh10 = (*hooks.offset(hooks_count as isize)).data;
    *fresh10 = new_hook_data;
    *hooks_p = hooks;
    *hooks_count_p = hooks_count.wrapping_add(1 as c_int as c_ulong);
    return AFL_RET_SUCCESS;
}
/* Adds a hook that gets called in the client for each new outgoing page the client creates. */
#[no_mangle]
pub unsafe extern "C" fn llmp_client_add_new_out_page_hook(
    client: *mut llmp_client,
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

/* Adds a hook that gets called in the broker for each new message the broker touches.
if the callback returns false, the message is not forwarded to the clients. */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_add_message_hook(
    broker: *mut llmp_broker_state,
    hook: Option<LlmpMessageHookFn>,
    data: *mut c_void,
) -> AflRet {
    return llmp_add_hook_generic(
        &mut (*broker).msg_hooks,
        &mut (*broker).msg_hook_count,
        ::std::mem::transmute::<Option<LlmpMessageHookFn>, *mut c_void>(hook),
        data,
    );
}
/* Allocate and set up the new broker instance. Afterwards, run with
 * broker_run.
 */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_init(mut broker: *mut llmp_broker_state) -> AflRet {
    memset(
        broker as *mut c_void,
        0 as c_int,
        ::std::mem::size_of::<llmp_broker_state>() as c_ulong,
    );
    /* let's create some space for outgoing maps */
    (*broker).broadcast_maps = afl_realloc(
        0 as *mut c_void,
        (1 as c_int as c_ulong).wrapping_mul(::std::mem::size_of::<afl_shmem>() as c_ulong),
    ) as *mut afl_shmem;
    if (*broker).broadcast_maps.is_null() {
        return AFL_RET_ALLOC;
    }
    (*broker).broadcast_map_count = 1 as c_int as c_ulong;
    (*broker).llmp_client_count = 0 as c_int as c_ulong;
    (*broker).llmp_clients = 0 as *mut llmp_broker_client_metadata;
    if llmp_new_page_shmem(
        _llmp_broker_current_broadcast_map(broker),
        -(1 as c_int) as c_ulong,
        ((1 as c_int) << 28 as c_int) as c_ulong,
    )
    .is_null()
    {
        afl_free((*broker).broadcast_maps as *mut c_void);
        return AFL_RET_ALLOC;
    }
    return AFL_RET_SUCCESS;
}
/* Clean up the broker instance */
#[no_mangle]
pub unsafe extern "C" fn llmp_broker_deinit(mut broker: *mut llmp_broker_state) {
    let mut i: c_ulong;
    i = 0 as c_int as c_ulong;
    while i < (*broker).broadcast_map_count {
        afl_shmem_deinit(&mut *(*broker).broadcast_maps.offset(i as isize));
        i = i.wrapping_add(1)
    }
    i = 0 as c_int as c_ulong;
    while i < (*broker).llmp_client_count {
        afl_shmem_deinit((*(*broker).llmp_clients.offset(i as isize)).cur_client_map);
        free((*(*broker).llmp_clients.offset(i as isize)).cur_client_map as *mut c_void);
        i = i.wrapping_add(1)
        // TODO: Properly clean up the client
    }
    afl_free((*broker).broadcast_maps as *mut c_void);
    (*broker).broadcast_map_count = 0 as c_int as c_ulong;
    afl_free((*broker).llmp_clients as *mut c_void);
    (*broker).llmp_client_count = 0 as c_int as c_ulong;
}
