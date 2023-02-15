/*!
This shows how llmp can be used directly, without libafl abstractions
*/
extern crate alloc;

#[cfg(feature = "std")]
use core::time::Duration;
#[cfg(feature = "std")]
use std::{thread, time};

#[cfg(feature = "std")]
use libafl::{
    bolts::{
        llmp::{self, Tag},
        shmem::{ShMemProvider, StdShMemProvider},
        ClientId,
    },
    Error,
};

#[cfg(feature = "std")]
const _TAG_SIMPLE_U32_V1: Tag = Tag(0x5130_0321);
#[cfg(feature = "std")]
const _TAG_MATH_RESULT_V1: Tag = Tag(0x7747_4331);
#[cfg(feature = "std")]
const _TAG_1MEG_V1: Tag = Tag(0xB111_1161);

/// The time the broker will wait for things to happen before printing a message
#[cfg(feature = "std")]
const BROKER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the broker may sleep between forwarding a new chunk of sent messages
#[cfg(feature = "std")]
const SLEEP_BETWEEN_FORWARDS: Duration = Duration::from_millis(5);

#[cfg(feature = "std")]
fn adder_loop(port: u16) -> ! {
    let shmem_provider = StdShMemProvider::new().unwrap();
    let mut client = llmp::LlmpClient::create_attach_to_tcp(shmem_provider, port).unwrap();
    let mut last_result: u32 = 0;
    let mut current_result: u32 = 0;
    loop {
        let mut msg_counter = 0;
        loop {
            let Some((sender, tag, buf)) = client.recv_buf().unwrap() else { break };
            msg_counter += 1;
            match tag {
                _TAG_SIMPLE_U32_V1 => {
                    current_result =
                        current_result.wrapping_add(u32::from_le_bytes(buf.try_into().unwrap()));
                }
                _ => println!(
                    "Adder Client ignored unknown message {:?} from client {:?} with {} bytes",
                    tag,
                    sender,
                    buf.len()
                ),
            };
        }

        if current_result != last_result {
            println!("Adder handled {msg_counter} messages, reporting {current_result} to broker");

            client
                .send_buf(_TAG_MATH_RESULT_V1, &current_result.to_le_bytes())
                .unwrap();
            last_result = current_result;
        }

        thread::sleep(time::Duration::from_millis(100));
    }
}

#[cfg(feature = "std")]
fn large_msg_loop(port: u16) -> ! {
    let mut client =
        llmp::LlmpClient::create_attach_to_tcp(StdShMemProvider::new().unwrap(), port).unwrap();

    #[allow(clippy::large_stack_arrays)]
    let meg_buf = [1u8; 1 << 20];

    loop {
        client.send_buf(_TAG_1MEG_V1, &meg_buf).unwrap();
        println!("Sending the next megabyte");
        thread::sleep(time::Duration::from_millis(100));
    }
}

#[allow(clippy::unnecessary_wraps)]
#[cfg(feature = "std")]
fn broker_message_hook(
    msg_or_timeout: Option<(ClientId, llmp::Tag, llmp::Flags, &[u8])>,
) -> Result<llmp::LlmpMsgHookResult, Error> {
    let (client_id, tag, _flags, message) = if let Some(msg) = msg_or_timeout {
        msg
    } else {
        println!(
            "No client did anything for {} seconds..",
            BROKER_TIMEOUT.as_secs()
        );
        return Ok(llmp::LlmpMsgHookResult::Handled);
    };

    match tag {
        _TAG_SIMPLE_U32_V1 => {
            println!(
                "Client {:?} sent message: {:?}",
                client_id,
                u32::from_le_bytes(message.try_into().unwrap())
            );
            Ok(llmp::LlmpMsgHookResult::ForwardToClients)
        }
        _TAG_MATH_RESULT_V1 => {
            println!(
                "Adder Client has this current result: {:?}",
                u32::from_le_bytes(message.try_into().unwrap())
            );
            Ok(llmp::LlmpMsgHookResult::Handled)
        }
        _ => {
            println!("Unknown message id received: {tag:?}");
            Ok(llmp::LlmpMsgHookResult::ForwardToClients)
        }
    }
}

#[cfg(not(feature = "std"))]
fn main() {
    eprintln!("LLMP example is currently not supported on no_std. Implement ShMem for no_std.");
}

#[cfg(feature = "std")]
fn main() {
    /* The main node has a broker, and a few worker threads */

    use std::num::NonZeroUsize;

    let mode = std::env::args()
        .nth(1)
        .expect("no mode specified, chose 'broker', 'b2b', 'ctr', 'adder', or 'large'");
    let port: u16 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "1337".into())
        .parse::<u16>()
        .unwrap();
    // in the b2b use-case, this is our "own" port, we connect to the "normal" broker node on startup.
    let b2b_port: u16 = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "4242".into())
        .parse::<u16>()
        .unwrap();
    println!("Launching in mode {mode} on port {port}");

    match mode.as_str() {
        "broker" => {
            let mut broker = llmp::LlmpBroker::new(StdShMemProvider::new().unwrap()).unwrap();
            broker.launch_tcp_listener_on(port).unwrap();
            // Exit when we got at least _n_ nodes, and all of them quit.
            broker.set_exit_cleanly_after(NonZeroUsize::new(2_usize).unwrap());
            broker.loop_with_timeouts(
                &mut broker_message_hook,
                BROKER_TIMEOUT,
                Some(Duration::from_millis(5)),
            );
        }
        "b2b" => {
            let mut broker = llmp::LlmpBroker::new(StdShMemProvider::new().unwrap()).unwrap();
            broker.launch_tcp_listener_on(b2b_port).unwrap();
            // connect back to the main broker.
            broker.connect_b2b(("127.0.0.1", port)).unwrap();
            broker.loop_with_timeouts(
                &mut broker_message_hook,
                BROKER_TIMEOUT,
                Some(Duration::from_millis(5)),
            );
        }
        "ctr" => {
            let mut client =
                llmp::LlmpClient::create_attach_to_tcp(StdShMemProvider::new().unwrap(), port)
                    .unwrap();
            let mut counter: u32 = 0;
            loop {
                counter = counter.wrapping_add(1);
                client
                    .send_buf(_TAG_SIMPLE_U32_V1, &counter.to_le_bytes())
                    .unwrap();
                println!("CTR Client writing {counter}");
                thread::sleep(Duration::from_secs(1));
            }
        }
        "adder" => {
            adder_loop(port);
        }
        "large" => {
            large_msg_loop(port);
        }
        _ => {
            println!("No valid mode supplied");
        }
    }
}
