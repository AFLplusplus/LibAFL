use core::convert::TryInto;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;
use std::thread;
use std::time;

use afl::events::llmp_translated::*;

const TAG_SIMPLE_U32_V1: u32 = 0x51300321;

fn llmp_test_clientloop(client: *mut llmp_client, _data: *mut c_void) -> ! {
    let mut counter: u32 = 0;
    loop {
        counter += 1;

        unsafe {
            let llmp_message = llmp_client_alloc_next(client, size_of::<u32>());
            std::ptr::copy(
                counter.to_be_bytes().as_ptr(),
                (*llmp_message).buf.as_mut_ptr(),
                size_of::<u32>(),
            );
            (*llmp_message).tag = TAG_SIMPLE_U32_V1;
            llmp_client_send(client, llmp_message);
        }

        thread::sleep(time::Duration::from_millis(100));
    }
}

fn broker_message_hook(
    _broker: *mut llmp_broker_state,
    client_metadata: *mut llmp_broker_client_metadata,
    message: *mut llmp_message,
    _data: *mut c_void,
) -> LlmpMessageHookResult {
    unsafe {
        match (*message).tag {
            TAG_SIMPLE_U32_V1 => {
                println!(
                    "Client {:?} sent message: {:?}",
                    (*client_metadata).pid,
                    u32::from_be_bytes(
                        std::slice::from_raw_parts((*message).buf.as_ptr(), size_of::<u32>())
                            .try_into()
                            .unwrap()
                    ),
                );
                LlmpMessageHookResult::Handled
            }
            _ => {
                println!("Unknwon message id received!");
                LlmpMessageHookResult::ForwardToClients
            }
        }
    }
}

fn main() {
    /* The main node has a broker, and a few worker threads */

    let thread_count = num_cpus::get() - 1;
    println!("Running with 1 broker and {} clients", thread_count);

    let mut broker = llmp_broker_state {
        last_msg_sent: ptr::null_mut(),
        broadcast_map_count: 0,
        broadcast_maps: ptr::null_mut(),
        msg_hook_count: 0,
        msg_hooks: ptr::null_mut(),
        llmp_client_count: 0,
        llmp_clients: ptr::null_mut(),
    };
    unsafe {
        llmp_broker_init(&mut broker).expect("Could not init");
        for i in 0..thread_count {
            println!("Adding client {}", i);
            llmp_broker_register_childprocess_clientloop(
                &mut broker,
                llmp_test_clientloop,
                ptr::null_mut(),
            )
            .expect("could not add child clientloop");
        }

        println!("Spawning broker");

        llmp_broker_add_message_hook(&mut broker, broker_message_hook, ptr::null_mut());

        llmp_broker_run(&mut broker);
    }
}
