# Hybrid Fuzzing for stb_image

This folder contains an example hybrid fuzzer for stb_image using SymCC.
It is based on the stb_image fuzzer that is also part of the examples.
It has been tested on Linux only, as SymCC only works on linux.

The fuzzer itself is in the `fuzzer` directory and the concolic runtime lives in `runtime`.

## Build

To build this example, run `cargo build --release` in the `runtime` and `fuzzer` directories separately (and in that order).
This will build the fuzzer like it does in the stb_image case, but _additionally_ builds a version of the target that is instrumented with SymCC concolic instrumentation (`harness_symcc.c`).
This separate version also doesn't conform to LibFuzzer's interface, but rather is a simple program that has the same behaviour as the LibFuzzer version (`harness.c`), because the SymCC runtime expects targets it's environment to be destroyed after a single execution (ie. it doesn't clean up it's resources).
Building the separate concolic version of the target also requires a concolic runtime, which is part of the `runtime` folder.
The build script of the fuzzer will check that the runtime has been built, but triggering the build command needs to be done manually (ie. run `cargo build (--release)` the runtime folder before building the fuzzer).
The build script will also build SymCC.
Therefore, all build depencies for SymCC should be available beforehand.

## Run

The first time you run the binary (`target/release/libfuzzer_stb_image_concolic`), the broker will open a tcp port (currently on port `1337`), waiting for fuzzer clients to connect. This port is local and only used for the initial handshake. All further communication happens via shared map, to be independent of the kernel.
