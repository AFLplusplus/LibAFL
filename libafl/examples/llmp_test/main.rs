/*!
This shows how llmp can be used directly, without libafl abstractions
*/
extern crate alloc;

#[cfg(all(unix, feature = "std"))]
use core::time::Duration;
#[cfg(all(unix, feature = "std"))]
use std::{thread, time};

use libafl::bolts::llmp::Tag;
#[cfg(all(unix, feature = "std"))]
use libafl::{
    bolts::{
        llmp,
        shmem::{ShMemProvider, StdShMemProvider},
    },
    Error,
};

const _TAG_SIMPLE_U32_V1: Tag = 0x51300321;
const _TAG_MATH_RESULT_V1: Tag = 0x77474331;
const _TAG_1MEG_V1: Tag = 0xB1111161;

#[cfg(all(unix, feature = "std"))]
fn adder_loop(port: u16) -> ! {
    let shmem_provider = StdShMemProvider::new().unwrap();
    let mut client = llmp::LlmpClient::create_attach_to_tcp(shmem_provider, port).unwrap();
    let mut last_result: u32 = 0;
    let mut current_result: u32 = 0;
    loop {
        let mut msg_counter = 0;
        loop {
            let (sender, tag, buf) = match client.recv_buf().unwrap() {
                None => break,
                Some(msg) => msg,
            };
            msg_counter += 1;
            match tag {
                _TAG_SIMPLE_U32_V1 => {
                    current_result =
                        current_result.wrapping_add(u32::from_le_bytes(buf.try_into().unwrap()));
                }
                _ => println!(
                    "Adder Client ignored unknown message {:#x} from client {} with {} bytes",
                    tag,
                    sender,
                    buf.len()
                ),
            };
        }

        if current_result != last_result {
            println!(
                "Adder handled {} messages, reporting {} to broker",
                msg_counter, current_result
            );

            client
                .send_buf(_TAG_MATH_RESULT_V1, &current_result.to_le_bytes())
                .unwrap();
            last_result = current_result;
        }

        thread::sleep(time::Duration::from_millis(100));
    }
}

#[cfg(all(unix, feature = "std"))]
fn large_msg_loop(port: u16) -> ! {
    let mut client =
        llmp::LlmpClient::create_attach_to_tcp(StdShMemProvider::new().unwrap(), port).unwrap();

    let meg_buf = [1u8; 1 << 20];

    loop {
        client.send_buf(_TAG_1MEG_V1, &meg_buf).unwrap();
        println!("Sending the next megabyte");
        thread::sleep(time::Duration::from_millis(100))
    }
}

#[cfg(all(unix, feature = "std"))]
fn broker_message_hook(
    client_id: u32,
    tag: llmp::Tag,
    _flags: llmp::Flags,
    message: &[u8],
) -> Result<llmp::LlmpMsgHookResult, Error> {
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
            println!("Unknwon message id received!");
            Ok(llmp::LlmpMsgHookResult::ForwardToClients)
        }
    }
}

#[cfg(not(unix))]
fn main() {
    todo!("LLMP is not yet supported on this platform.");
}

#[cfg(unix)]
fn main() {
    /* The main node has a broker, and a few worker threads */

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
    println!("Launching in mode {} on port {}", mode, port);

    match mode.as_str() {
        "broker" => {
            let mut broker = llmp::LlmpBroker::new(StdShMemProvider::new().unwrap()).unwrap();
            broker.launch_tcp_listener_on(port).unwrap();
            broker.loop_forever(&mut broker_message_hook, Some(Duration::from_millis(5)))
        }
        "b2b" => {
            let mut broker = llmp::LlmpBroker::new(StdShMemProvider::new().unwrap()).unwrap();
            broker.launch_tcp_listener_on(b2b_port).unwrap();
            // connect back to the main broker.
            broker.connect_b2b(("127.0.0.1", port)).unwrap();
            broker.loop_forever(&mut broker_message_hook, Some(Duration::from_millis(5)))
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
                println!("CTR Client writing {}", counter);
                thread::sleep(Duration::from_secs(1))
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
