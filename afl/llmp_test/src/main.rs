extern crate alloc;

use core::convert::TryInto;
use core::time::Duration;
use std::thread;
use std::time;

use afl::events::llmp;

const TAG_SIMPLE_U32_V1: u32 = 0x51300321;
const TAG_MATH_RESULT_V1: u32 = 0x77474331;

fn adder_loop(port: u16) -> ! {
    let mut client = llmp::LlmpClient::create_attach_to_tcp(port).unwrap();
    let mut last_result: u32 = 0;
    let mut current_result: u32 = 0;
    loop {
        let mut msg_counter = 0;
        loop {
            let (tag, buf) = match client.recv_buf().unwrap() {
                None => break,
                Some(msg) => msg,
            };
            msg_counter += 1;
            match tag {
                TAG_SIMPLE_U32_V1 => {
                    current_result =
                        current_result.wrapping_add(u32::from_le_bytes(buf.try_into().unwrap()));
                }
                _ => println!("Adder Client ignored unknown message {}", tag),
            };
        }

        if current_result != last_result {
            println!(
                "Adder handled {} messages, reporting {} to broker",
                msg_counter, current_result
            );

            client
                .send_buf(TAG_MATH_RESULT_V1, &current_result.to_le_bytes())
                .unwrap();
            last_result = current_result;
        }

        thread::sleep(time::Duration::from_millis(100));
    }
}

unsafe fn broker_message_hook(
    client_id: u32,
    message: *mut llmp::LlmpMsg,
) -> llmp::LlmpMsgHookResult {
    match (*message).tag {
        TAG_SIMPLE_U32_V1 => {
            println!(
                "Client {:?} sent message: {:?}",
                client_id,
                u32::from_le_bytes((*message).as_slice().try_into().unwrap())
            );
            llmp::LlmpMsgHookResult::ForwardToClients
        }
        TAG_MATH_RESULT_V1 => {
            println!(
                "Adder Client has this current result: {:?}",
                u32::from_le_bytes((*message).as_slice().try_into().unwrap())
            );
            llmp::LlmpMsgHookResult::Handled
        }
        _ => {
            println!("Unknwon message id received!");
            llmp::LlmpMsgHookResult::ForwardToClients
        }
    }
}

fn main() {
    /* The main node has a broker, and a few worker threads */

    let mode = std::env::args()
        .nth(1)
        .expect("no mode specified, chose 'broker', 'ctr', or 'adder'");
    let port: u16 = std::env::args()
        .nth(2)
        .unwrap_or("1337".into())
        .parse::<u16>()
        .unwrap();
    println!("Launching in mode {} on port {}", mode, port);

    match mode.as_str() {
        "broker" => {
            let mut broker: llmp::LlmpBroker = llmp::LlmpBroker::new().unwrap();
            broker.launch_tcp_listener(port).unwrap();
            broker.add_message_hook(broker_message_hook);
            broker.loop_forever(Some(Duration::from_millis(5)))
        }
        "ctr" => {
            let mut client = llmp::LlmpClient::create_attach_to_tcp(port).unwrap();
            let mut counter: u32 = 0;
            loop {
                counter = counter.wrapping_add(1);
                client
                    .send_buf(TAG_SIMPLE_U32_V1, &counter.to_le_bytes())
                    .unwrap();
            }
        }
        "adder" => {
            adder_loop(port);
        }
        _ => {
            println!("No valid mode supplied");
        }
    }
}
