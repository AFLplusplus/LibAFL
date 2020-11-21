use std::env::args;
use std::ptr;

use afl::events::llmp_translated;

fn main() {

    let thread_count = 1;

    /* The main node has a broker, a tcp server, and a few worker threads */

    let mut broker = llmp_translated::llmp_broker_state {
        last_msg_sent: ptr::null_mut(),
        broadcast_map_count: 0,
        broadcast_maps: ptr::null_mut(),
        msg_hook_count: 0,
        msg_hooks: ptr::null_mut(),
        llmp_client_count: 0,
        llmp_clients: ptr::null_mut(),
    };
    unsafe {llmp_translated::llmp_broker_init(&mut broker)};

    /*
    llmp_broker_register_local_server(broker, port);

    if (!llmp_broker_register_threaded_clientloop(broker, llmp_clientloop_print_u32, NULL)) {

      FATAL("error adding threaded client");

    }

    int i;
    for (i = 0; i < thread_count; i++) {

      if (!llmp_broker_register_threaded_clientloop(broker, llmp_clientloop_rand_u32, NULL)) {

        FATAL("error adding threaded client");

      }

    }

    OKF("Spawning main on port %d", port);
    llmp_broker_run(broker);

  } else {

    if (thread_count > 1) { WARNF("Multiple threads not supported for clients."); }

    OKF("Client will connect to port %d", port);
    // Worker only needs to spawn client threads.
    llmp_client_t *client_state = llmp_client_new(port);
    if (!client_state) { FATAL("Error connecting to broker at port %d", port); }
    llmp_clientloop_rand_u32(client_state, NULL);

  }

  FATAL("Unreachable");


    println!("Hello, world!");
    */
}
