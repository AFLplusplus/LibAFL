# Libfuzzer for libpng (cmp+alloc)

This folder contains an example fuzzer for libpng, using LLMP for fast multi-process fuzzing and crash detection.
To show off crash detection, we added a ud2 instruction to the harness, edit harness.cc if you want a non-crashing example.
It has been tested on Linux.

The difference between the normal Libfuzzer for libpng example here is that this fuzzer is not just using edge coverage as feedback but also comparisons values (-value-profile like) and allocations sizes.
This is an example how multiple feedbacks can be combined in a fuzzer.

## Build

To build this example, run `cargo build --example libfuzzer_libpng_cmpalloc --release`.
This will call (the build.rs)[./builld.rs], which in turn downloads a libpng archive from the web.
Then, it will link (the fuzzer)[./src/fuzzer.rs] against (the C++ harness)[./harness.cc] and the instrumented `libpng`.
Afterwards, the fuzzer will be ready to run, from `../../target/examples/libfuzzer_libpng_cmpalloc`.

## Run

The first time you run the binary, the broker will open a tcp port (currently on port `1337`), waiting for fuzzer clients to connect. This port is local and only used for the initial handshake. All further communication happens via shared map, to be independent of the kernel.

Each following execution will run a fuzzer client.
As this example uses in-process fuzzing, we added a Restarting Event Manager (`setup_restarting_mgr`).
This means each client will start itself again to listen for crashes and timeouts.
By restarting the actual fuzzer, it can recover from these exit conditions.

In any real-world scenario, you should use `taskset` to pin each client to an empty CPU core, the lib does not pick an empty core automatically (yet).

For convenience, you may just run `./test.sh` in this folder to test it.
