# Libfuzzer for libpng

This folder contains an example fuzzer for libpng, using LLMP for fast multi-process fuzzing and crash detection.
To show off crash detection, we added a `ud2` instruction to the harness, edit harness.cc if you want a non-crashing example.
It has been tested on Linux.

## Build

To build this example, run `cargo build --release`.
This will build the library with the fuzzer (src/lib.rs) with the libfuzzer compatibility layer and the SanitizerCoverage runtime functions for coverage feedback.
In addition, it will build also two C and C++ compiler wrappers (bin/c(c/xx).rs) that you must use to compile the target.

Then download libpng from https://deac-fra.dl.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz and unpack the archive.

Now compile it with:

```
cd libpng-1.6.37
./configure
make CC=/path/to/libfuzzer_libpng/target/release/cc -j `nproc`
```

You can find the static lib at `libpng-1.6.37/.libs/libpng16.a`.

Now, we have to build the libfuzzer harness and link all togheter to create our fuzzer binary.

```
/path/to/libfuzzer_libpng/target/debug/cxx /path/to/libfuzzer_libpng/harness.cc libpng-1.6.37/.libs/libpng16.a -I libpng-1.6.37/ -o fuzzer -lz -lm
```

Afterwards, the fuzzer will be ready to run simply executing `./fuzzer`.

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

