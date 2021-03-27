# Libfuzzer for libpng

This folder contains an example fuzzer for libpng, using LLMP for fast multi-process fuzzing and crash detection.
To show off crash detection, we added a `ud2` instruction to the harness, edit harness.cc if you want a non-crashing example.
It has been tested on Linux.

## Build

You will need `clang` and `clang++` along with basic build dependencies for this example to compile.
To build this example, run `cargo build --example libfuzzer_libpng --release`.
This will call [the build.rs](./build.rs), which in turn downloads a libpng archive from the web.
Then, it will link [the fuzzer](./src/fuzzer.rs) against [the C++ harness](./harness.cc) and the instrumented `libpng`.
Afterwards, the fuzzer will be ready to run, from `../../target/examples/libfuzzer_libpng`.

## Run

The first time you run the binary, the broker will open a tcp port (currently on port `1337`), waiting for fuzzer clients to connect. This port is local and only used for the initial handshake. All further communication happens via shared map, to be independent of the kernel. Currently you must run the clients from the libfuzzer_libpng directory for them to be able to access the PNG corpus.

```
cargo run --release --example libfuzzer_libpng

[libafl/src/bolts/llmp.rs:407] "We're the broker" = "We\'re the broker"
Doing broker things. Run this tool again to start fuzzing in a client.
```

And after running the above again in a separate terminal:

```
[libafl/src/bolts/llmp.rs:1464] "New connection" = "New connection"
[libafl/src/bolts/llmp.rs:1464] addr = 127.0.0.1:33500
[libafl/src/bolts/llmp.rs:1464] stream.peer_addr().unwrap() = 127.0.0.1:33500
[LOG Debug]: Loaded 4 initial testcases.
[New Testcase #2] clients: 3, corpus: 6, objectives: 0, executions: 5, exec/sec: 0
< fuzzing stats >
```

As this example uses in-process fuzzing, we added a Restarting Event Manager (`setup_restarting_mgr`).
This means each client will start itself again to listen for crashes and timeouts.
By restarting the actual fuzzer, it can recover from these exit conditions.

In any real-world scenario, you should use `taskset` to pin each client to an empty CPU core, the lib does not pick an empty core automatically (yet).

For convenience, you may just run `./test.sh` in this folder to test it.
