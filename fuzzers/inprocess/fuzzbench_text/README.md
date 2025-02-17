# Fuzzbench Harness (text)

This folder contains an example fuzzer tailored for fuzzbench.
It uses the best possible setting, with the exception of a SimpleRestartingEventManager instead of an LlmpRestartEventManager - since fuzzbench is single threaded.
Real fuzz campaigns should consider using multithreaded LlmpRestartEventManager, see the other examples.

This fuzzer autodetect if the passed-in tokens and the initial inputs are text or binary data, and enables Grimoire in case of text.

## Build

To build this example, run `cargo build --release`.
This will build the fuzzer compilers (`libafl_cc` and `libafl_cpp`) with `src/lib.rs` as fuzzer.
The fuzzer uses the libfuzzer compatibility layer and the SanitizerCoverage runtime functions for coverage feedback.

These can then be used to build libfuzzer harnesses in the software project of your choice.
Finally, just run the resulting binary with `out_dir`, `in_dir`.

In any real-world scenario, you should use `taskset` to pin each client to an empty CPU core, the lib does not pick an empty core automatically (yet).

