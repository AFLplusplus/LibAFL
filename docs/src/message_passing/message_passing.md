# Message Passing

LibAFL offers a standard mechanism for message passing between processes and machines with a low overhead.
We use message passing to inform the other connected clients/fuzzers/nodes about new testcases, metadata, and statistics about the current run.
Depending on individual needs, LibAFL can also write testcase contents to disk, while still using events to notify other fuzzers, using the `CachedOnDiskCorpus` or similar.

In our tests, message passing scales very well to share new testcases and metadata between multiple running fuzzer instances for multi-core fuzzing.
Specifically, it scales _a lot_ better than using memory locks on a shared corpus, and _a lot_ better than sharing the testcases via the filesystem, as AFL traditionally does.
Think "all cores are green" in `htop`, aka., no kernel interaction.

The `EventManager` interface is used to send Events over the wire using `Low Level Message Passing`, a custom message passing mechanism over shared memory or TCP.

## Low Level Message Passing (LLMP)

LibAFL comes with a reasonably lock-free message passing mechanism that scales well across cores and, using its _broker2broker_ mechanism, even to connected machines via TCP.
Most example fuzzers use this mechanism, and it is the best `EventManager` if you want to fuzz on more than a single core.
In the following, we will describe the inner workings of `LLMP`.

`LLMP` has one `broker` process that can forward messages sent by any client process to all other clients.
The broker can also intercept and filter the messages it receives instead of forwarding them.
A common use-case for messages filtered by the broker are the status messages sent from each client to the broker directly.
The broker used this information to paint a simple UI, with up-to-date information about all clients, however the other clients don't need to receive this information.

### Speedy Local Messages via Shared Memory

Throughout LibAFL, we use a wrapper around different operating system's shared maps, called `ShMem`.
Shared maps, called shared memory for the sake of not colliding with Rust's `map()` functions, are the backbone of `LLMP`.
Each client, usually a fuzzer trying to share stats and new testcases, maps an outgoing `ShMem` map.
With very few exceptions, only this client writes to this map, therefore, we do not run in race conditions and can live without locks.
The broker reads from all client's `ShMem` maps.
It periodically checks all incoming client maps and then forwards new messages to its outgoing broadcast-`ShMem`, mapped by all connected clients.

To send new messages, a client places a new message at the end of their shared memory and then updates a static field to notify the broker.
Once the outgoing map is full, the sender allocates a new `ShMem` using the respective `ShMemProvider`.
It then sends the information needed to map the newly-allocated page in connected processes to the old page, using an end of page (`EOP`) message.
Once the receiver maps the new page, it flags it as safe for unmapping by the sending process (to avoid race conditions if we have more than a single EOP in a short time), and then continues to read from the new `ShMem`.

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
On `std` builds, the broker will sleep a few milliseconds after a loop, since we do not need the messages to arrive instantly.
After the broker received a new message from clientN, (`clientN_out->current_id != last_message->message_id`) the broker copies the message content to its own broadcast shared memory.

The clients periodically, for example after finishing `n` mutations, check for new incoming messages by checking if (`current_broadcast_map->current_id != last_message->message_id`).
While the broker uses the same EOP mechanism to map new `ShMem`s for its outgoing map, it never unmaps old pages.
This additional memory resources serve a good purpose: by keeping all broadcast pages around, we make sure that new clients can join in on a fuzzing campaign at a later point in time.
They just need to re-read all broadcasted messages from start to finish.

So the outgoing messages flow is like this over the outgoing broadcast `Shmem`:

```text
[broker]
  |
[current_broadcast_shmem]
  |
  |___________________________________
  |_________________                  \
  |                 \                  \
  |                  |                  |
 \|/                \|/                \|/
[client0]        [client1]    ...    [clientN]
```

To use `LLMP` in LibAFL, you usually want to use an `LlmpRestartingEventManager` or its restarting variant.
They are the default if using LibAFL's `Launcher`.

If you should want to use `LLMP` in its raw form, without any `LibAFL` abstractions, take a look at the `llmp_test` example in [./libafl/examples](https://github.com/AFLplusplus/LibAFL/blob/main/libafl_bolts/examples/llmp_test/main.rs).
You can run the example using `cargo run --example llmp_test` with the appropriate modes, as indicated by its help output.
First, you will have to create a broker using `LlmpBroker::new()`.
Then, create some `LlmpClient`s in other threads and register them with the main thread using `LlmpBroker::register_client`.
Finally, call `LlmpBroker::loop_forever()`.

### B2B: Connecting Fuzzers via TCP

For `broker2broker` communication, all broadcast messages are additionally forwarded via network sockets.
To facilitate this, we spawn an additional client thread in the broker, that reads the broadcast shared memory, just like any other client would.
For broker2broker communication, this b2b client listens for TCP connections from other, remote brokers.
It keeps a pool of open sockets to other, remote, b2b brokers around at any time.
When receiving a new message on the local broker shared memory, the b2b client will forward it to all connected remote brokers via TCP.
Additionally, the broker can receive messages from all connected (remote) brokers, and forward them to the local broker over a client `ShMem`.

As a sidenote, the tcp listener used for b2b communication is also used for an initial handshake when a new client tries to connect to a broker locally, simply exchanging the initial `ShMem` descriptions.
