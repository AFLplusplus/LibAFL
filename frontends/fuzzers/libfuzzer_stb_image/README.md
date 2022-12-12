# Libfuzzer for stb_image

This folder contains an example fuzzer for stb_image, using LLMP for fast multi-process fuzzing and crash detection.
It has been tested on Linux and Windows.

## Build

To build this example, run `cargo build --release`.
This will build the the fuzzer (src/main.rs) with the libfuzzer compatibility layer and the SanitizerCoverage runtime functions for coverage feedback as a standalone binary.

Unlike the libpng example, in this example the harness (that entirely includes the program under test) is compiled in the `build.rs` file while building the crate, and linked with the fuzzer by cargo when producing the final binary, `target/release/libfuzzer_stb_image`.

## Run

The first time you run the binary (`target/release/libfuzzer_stb_image`), the broker will open a tcp port (currently on port `1337`), waiting for fuzzer clients to connect. This port is local and only used for the initial handshake. All further communication happens via shared map, to be independent of the kernel.

Each following execution will run a fuzzer client.
As this example uses in-process fuzzing, we added a Restarting Event Manager (`setup_restarting_mgr`).
This means each client will start itself again to listen for crashes and timeouts.
By restarting the actual fuzzer, it can recover from these exit conditions.

In any real-world scenario, you should use `taskset` to pin each client to an empty CPU core, the lib does not pick an empty core automatically (yet).

