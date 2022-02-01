# Backtrace baby fuzzers

The projects contained in this directory are simple fuzzers derived from the original baby_fuzzer examples, whose perpose is to show how to use a `BacktraceObserver` or an `ASANObserver` to dedupe crashes and other necessary component for this feature.

The examples cover:

- An `InProcessForkExecutor` fuzzing a C harness
- An `InProcessForkExecutor` fuzzing a Rust harness
- An `InProcessExecutor` fuzzing a C harness
- An `InProcessExecutor` fuzzing a Rust harness
- A `CommandExecutor` fuzzing a simple binary
- A `ForkServerExecutor` fuzzing a simple binary
