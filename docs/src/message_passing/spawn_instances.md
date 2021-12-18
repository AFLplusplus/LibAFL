# Spawning Instances

Multiple fuzzer instances can be spawned using different ways.

## Manually, via a TCP port

The straightforward way to do Multi-Threading is to use the `LlmpRestartingEventManager`, specifically to use `setup_restarting_mgr_std`.
It abstracts away all the pesky details about restarts on crash handling (for in-memory fuzzers) and multi-threading.
With it, every instance you launch manually tries to connect to a TCP port on the local machine.

If the port is not yet bound, this instance becomes the broker, itself binding to the port to await new clients.

If the port is already bound, the EventManager will try to connect to it.
The instance becomes a client and can now communicate with all other nodes.

Launching nodes manually has the benefit that you can have multiple nodes with different configurations, such as clients fuzzing with and without ASAN.

While it's called "restarting" manager, it uses `fork` on Unix operating systems as optimization and only actually restarts from scratch on Windows.

## Launcher

The Launcher is the lazy way to do multiprocessing.
You can use the Launcher builder to create a fuzzer that spawns multiple nodes, all using restarting event managers.
An example may look like this:

```rust,ignore
    Launcher::builder()
        .configuration(EventConfig::from_name(&configuration))
        .shmem_provider(shmem_provider)
        .monitor(mon)
        .run_client(&mut run_client)
        .cores(cores)
        .broker_port(broker_port)
        .stdout_file(stdout_file)
        .remote_broker_addr(broker_addr)
        .build()
        .launch()
```

This first starts a broker, then spawns `n` clients, according to the value passed to `cores`.
The value is a string indicating the cores to bind to, for example, `0,2,5` or `0-3`.
For each client, `run_client` will be called.
On Windows, the Launcher will restart each client, while on Unix, it will use `fork`.

## Other ways

The LlmpEvenManager family is the easiest way to do spawn instances, but for obscure targets, you may need to come up with other solutions.
LLMP is even, in theory, `no_std` compatible, and even completely different EventManagers can be used for message passing.
If you are in this situation, please either read through the current implementations and/or reach out to us.