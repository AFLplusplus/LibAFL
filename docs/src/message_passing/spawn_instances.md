# Spawning Instances

Multiple fuzzer instances can be spawned using different ways.

## Manually, via a TCP port

The straightforward way to do Multi-Threading is to use the `LlmpRestartingEventManager`, specifically to use `setup_restarting_mgr_std`.
It abstracts away all the pesky details about restarts on crash handling (for in-memory fuzzers) and multi-threading.
With it, every instance you launch manually tries to connect to a TCP port on the local machine.

If the port is not yet bound, this instance becomes the broker, binding itself to the port to await new clients.

If the port is already bound, the EventManager will try to connect to it.
The instance becomes a client and can now communicate with all other nodes.

Launching nodes manually has the benefit that you can have multiple nodes with different configurations, such as clients fuzzing with and without ASAN.

While it's called "restarting" manager, it uses `fork` on Unix-like operating systems as optimization and only actually restarts from scratch on Windows.


## Automated, with Launcher

The Launcher is the lazy way to do multiprocessing.
You can use the Launcher builder to create a fuzzer that spawns multiple nodes with one click, all using restarting event managers and the same configuration.

To use launcher, first you need to write an anonymous function `let mut run_client = |state: Option<_>, mut mgr, _core_id|{}`, which uses three parameters to create an individual fuzzer. Then you can specify the `shmem_provider`,`broker_port`,`monitor`,`cores` and other stuff through `Launcher::builder()`:

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
On Windows, the Launcher will restart each client, while on Unix-alikes, it will use `fork`.

Advanced use-cases:

1. To connect multiple nodes together via TCP, you can use the `remote_broker_addr`. this requires the `llmp_bind_public` compile-time feature for `LibAFL`.
2. To use multiple launchers for individual configurations, you can set `spawn_broker` to `false` on all instances but one.
3. Launcher will not select the cores automatically, so you need to specify the `cores` that you want.

For more examples, you can check out `qemu_launcher` and `libfuzzer_libpng_launcher` in [`./fuzzers/`](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers).

## Other ways

The `LlmpEventManager` family is the easiest way to spawn instances, but for obscure targets, you may need to come up with other solutions.
LLMP is even, in theory, `no_std` compatible, and even completely different EventManagers can be used for message passing.
If you are in this situation, please either read through the current implementations and/or reach out to us.
