use core::ffi::c_void;

use std::env::args;
use std::ptr;

use afl::events::llmp_translated::*;

fn llmp_test_clientloop(client: *mut llmp_client, _data: *mut c_void) {
    println!("Client says hi");
}

fn main() {
    let thread_count = 1;

    /* The main node has a broker, a tcp server, and a few worker threads */

    let mut broker = llmp_broker_state {
        last_msg_sent: ptr::null_mut(),
        broadcast_map_count: 0,
        broadcast_maps: ptr::null_mut(),
        msg_hook_count: 0,
        msg_hooks: ptr::null_mut(),
        llmp_client_count: 0,
        llmp_clients: ptr::null_mut(),
    };
    let thread_count = 4;
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
        llmp_broker_run(&mut broker);
    }
}
