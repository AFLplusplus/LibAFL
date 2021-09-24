# Libfuzzer for stb_image with libafl_sugar

This folder contains an example fuzzer for stb_image, using LLMP for fast multi-process fuzzing and crash detection.
It has been tested on Linux and Windows.

## Build

To build this example, run `cargo build --release`.
This will build the the fuzzer (src/main.rs) with the libfuzzer compatibility layer and the SanitizerCoverage runtime functions for coverage feedback as a standalone binary.

Unlike the libpng example, in this example the harness (that entirely includes the program under test) is compiled in the `build.rs` file while building the crate, and linked with the fuzzer by cargo when producing the final binary, `target/release/libfuzzer_stb_image`.
