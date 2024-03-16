/*!
This shows how llmp can be used directly, without libafl abstractions
*/
extern crate alloc;

#[cfg(not(target_os = "haiku"))]
use core::time::Duration;
#[cfg(all(feature = "std", not(target_os = "haiku")))]
use std::{num::NonZeroUsize, thread, time};

#[cfg(all(feature = "std", not(target_os = "haiku")))]
use libafl_bolts::{
    llmp::{self, Tag},
    shmem::{ShMemProvider, StdShMemProvider},
    ClientId, Error, SimpleStderrLogger,
};

#[cfg(all(feature = "std", not(target_os = "haiku")))]
const _TAG_SIMPLE_U32_V1: Tag = Tag(0x5130_0321);
#[cfg(all(feature = "std", not(target_os = "haiku")))]
const _TAG_MATH_RESULT_V1: Tag = Tag(0x7747_4331);
#[cfg(all(feature = "std", not(target_os = "haiku")))]
const _TAG_1MEG_V1: Tag = Tag(0xB111_1161);

/// The time the broker will wait for things to happen before printing a message
#[cfg(all(feature = "std", not(target_os = "haiku")))]
const BROKER_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the broker may sleep between forwarding a new chunk of sent messages
#[cfg(all(feature = "std", not(target_os = "haiku")))]
const SLEEP_BETWEEN_FORWARDS: Duration = Duration::from_millis(5);

#[cfg(all(feature = "std", not(target_os = "haiku")))]
static LOGGER: SimpleStderrLogger = SimpleStderrLogger::new();

#[cfg(all(feature = "std", not(target_os = "haiku")))]
fn adder_loop(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let shmem_provider = StdShMemProvider::new()?;
    let mut client = llmp::LlmpClient::create_attach_to_tcp(shmem_provider, port)?;
    let mut last_result: u32 = 0;
    let mut current_result: u32 = 0;
    loop {
        let mut msg_counter = 0;
        loop {
            let Some((sender, tag, buf)) = client.recv_buf()? else {
                break;
            };
            msg_counter += 1;
            match tag {
                _TAG_SIMPLE_U32_V1 => {
                    current_result =
                        current_result.wrapping_add(u32::from_le_bytes(buf.try_into()?));
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

            client.send_buf(_TAG_MATH_RESULT_V1, &current_result.to_le_bytes())?;
            last_result = current_result;
        }

        thread::sleep(time::Duration::from_millis(100));
    }
}

#[cfg(all(feature = "std", not(target_os = "haiku")))]
fn large_msg_loop(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = llmp::LlmpClient::create_attach_to_tcp(StdShMemProvider::new()?, port)?;

    #[cfg(not(target_vendor = "apple"))]
    let meg_buf = vec![1u8; 1 << 20];
    #[cfg(target_vendor = "apple")]
    let meg_buf = vec![1u8; 1 << 19];

    loop {
        client.send_buf(_TAG_1MEG_V1, &meg_buf)?;
        #[cfg(not(target_vendor = "apple"))]
        println!("Sending the next megabyte");
        #[cfg(target_vendor = "apple")]
        println!("Sending the next half megabyte (Apple had issues with >1 meg)");
        thread::sleep(time::Duration::from_millis(100));
    }
}

#[allow(clippy::unnecessary_wraps)]
#[cfg(all(feature = "std", not(target_os = "haiku")))]
fn broker_message_hook(
    msg_or_timeout: Option<(ClientId, llmp::Tag, llmp::Flags, &[u8])>,
) -> Result<llmp::LlmpMsgHookResult, Error> {
    let Some((client_id, tag, _flags, message)) = msg_or_timeout else {
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
                u32::from_le_bytes(message.try_into()?)
            );
            Ok(llmp::LlmpMsgHookResult::ForwardToClients)
        }
        _TAG_MATH_RESULT_V1 => {
            println!(
                "Adder Client has this current result: {:?}",
                u32::from_le_bytes(message.try_into()?)
            );
            Ok(llmp::LlmpMsgHookResult::Handled)
        }
        _ => {
            println!("Unknown message id received: {tag:?}");
            Ok(llmp::LlmpMsgHookResult::ForwardToClients)
        }
    }
}

#[cfg(target_os = "haiku")]
fn main() {
    eprintln!("LLMP example is currently not supported on no_std. Implement ShMem for no_std.");
}

#[cfg(not(target_os = "haiku"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    /* The main node has a broker, and a few worker threads */

    let mode = std::env::args()
        .nth(1)
        .expect("no mode specified, chose 'broker', 'b2b', 'ctr', 'adder', 'large', or 'exiting'");
    let port: u16 = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "1337".into())
        .parse::<u16>()?;
    // in the b2b use-case, this is our "own" port, we connect to the "normal" broker node on startup.
    let b2b_port: u16 = std::env::args()
        .nth(3)
        .unwrap_or_else(|| "4242".into())
        .parse::<u16>()?;

    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    println!("Launching in mode {mode} on port {port}");

    match mode.as_str() {
        "broker" => {
            let mut broker =
                llmp::LlmpBroker::new(StdShMemProvider::new()?, Duration::from_secs(5))?;
            broker.launch_tcp_listener_on(port)?;
            // Exit when we got at least _n_ nodes, and all of them quit.
            broker.set_exit_cleanly_after(NonZeroUsize::new(1_usize).unwrap());
            broker.loop_with_timeouts(
                &mut broker_message_hook,
                BROKER_TIMEOUT,
                Some(SLEEP_BETWEEN_FORWARDS),
            );
        }
        "b2b" => {
            let mut broker =
                llmp::LlmpBroker::new(StdShMemProvider::new()?, Duration::from_secs(5))?;
            broker.launch_tcp_listener_on(b2b_port)?;
            // connect back to the main broker.
            broker.connect_b2b(("127.0.0.1", port))?;
            broker.loop_with_timeouts(
                &mut broker_message_hook,
                BROKER_TIMEOUT,
                Some(SLEEP_BETWEEN_FORWARDS),
            );
        }
        "ctr" => {
            let mut client =
                llmp::LlmpClient::create_attach_to_tcp(StdShMemProvider::new()?, port)?;
            let mut counter: u32 = 0;
            loop {
                counter = counter.wrapping_add(1);
                client.send_buf(_TAG_SIMPLE_U32_V1, &counter.to_le_bytes())?;
                println!("CTR Client writing {counter}");
                thread::sleep(Duration::from_secs(1));
            }
        }
        "adder" => {
            adder_loop(port)?;
        }
        "large" => {
            large_msg_loop(port)?;
        }
        "exiting" => {
            let mut client =
                llmp::LlmpClient::create_attach_to_tcp(StdShMemProvider::new()?, port)?;
            for i in 0..10_u32 {
                client.send_buf(_TAG_SIMPLE_U32_V1, &i.to_le_bytes())?;
                println!("Exiting Client writing {i}");
                thread::sleep(Duration::from_millis(10));
            }
            log::info!("Exiting Client exits");
            client.sender_mut().send_exiting()?;
        }
        _ => {
            println!("No valid mode supplied");
        }
    }
    Ok(())
}
