# Message Passing

LibAFL offers a standard mechanism for message passing over processes and machines with a low overhead.
We use message passing to inform the other connected clients/fuzzers/nodes about new testcases, metadata, and statistics about the current run.

The `EventManager` interface is used to send Events over the wire using `Low Level Message Passing`, a custom message passing mechanism over shared memory or TCP.

## Low Level Message Passing (LLMP)

LibAFL comes with a reasonably lock-free message passing mechanism that scales well across cores and, using its *broker2broker* mechanism, even to connected machines via TCP.
Most example fuzzers use this mechanism, and it is the best `EventManager` if you want to fuzz on more than a single core.
In the following, we will describe the inner workings of `LLMP`.

`LLMP` has one `broker` process that can forward messages sent by any client process to all other clients.
The broker can also intercept and filter the messages it receives instead of forwarding them.
A common use-case for messages filtered by the broker are the status messages sent from each client to the broker directly.
The broker used this information to paint a simple UI, with up-to-date information about all clients, however the other clients don't need to receive this information.

Each client has an outgoing `ShMem` shared memory map, to which only the client may write to.
The broker listens on all incoming client maps, and forwards messages to an outgoing broadcast-`ShMem`, mapped by all connected clients.
To send new messages, a client place a new message at the end of their map, and then updates a static field in the map.
If any outgoing map is filled up, the sender allocates a new `ShMem` using the respective `ShMemProvider` and sends the information needed to map the next page on the old page, using an end of page (`EOP`) message.
Once the receiver maps the new page, flags it as safe for unmapping from the sending process (to avoid race conditions if we have more than a single EOP in a short time), and then continues to read from the new `ShMem`.

The schema for client's maps to the broker is as follows:
```text
[client0]        [client1]    ...    [clientN]
  |                  |                 /
[client0_out] [client1_out] ... [clientN_out]
  |                 /                /
  |________________/                /
  |________________________________/
 \|/
[broker]
```

The broker loops over all incoming maps, and checks for new messages.
On `std` builds, the broker will sleep a few milliseconds in-between, since we do not need the messages to arrive instantly for our use-case.
After the broker received a new message from clientN, (`clientN_out->current_id != last_message->message_id`) the broker copies the message content to its own broadcast map.

The clients periodically, for example after finishing `n` mutations, check for new incoming messages by checking if (`current_broadcast_map->current_id != last_message->message_id`).
While the broker uses the same EOP mechanism to map new `ShMem`s for its outgoing map, it never unmaps old pages.
This way, new clients can join in on a fuzzing campaign at a later point in time, by re-reading all messages from start to finish - at the tradeoff of additional memory overhead.

So the outgoing messages flow like this over the outgoing broadcast `Shmem`:

```text
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
```

To use, you usually want to use an `LlmpEventManager` or the restarting variant.

If you should want to use `LLMP` in its raw form, without the added `LibAFL` abstractions, take a look at the `llmp_test` example in ./libafl/examples.
You can run the example using `cargo run --example llmp_test` with the appropriate modes, as indicated by its help output.
For this will have to create a broker using [`LlmpBroker::new()`].
Then, create some [`LlmpClient`]`s` in other threads and register them
with the main thread using [`LlmpBroker::register_client`].
Finally, call [`LlmpBroker::loop_forever()`].

For `broker2broker` communication, all broadcast messages are additionally forwarded via network sockets.
To facilitate this, we spawn an additional client thread in the broker, that reads the broadcast map like any other client would.
When receiving a new message on the broker map, it will forward it to all connected clients via tcp.
Additionally, it can receive messages from all connected (remote) brokers, and forward them to the local broker over a client `ShMem`.
