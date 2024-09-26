# LibAFL Fuzzers

## Example fuzzers

You can find here all the example fuzzers built on top of LibAFL.
They are sorted by fuzzer types:

- `baby`: Minimal fuzzers demonstrating a specific feature.
- `binary-only`: Fuzzers for binary-only targets.
- `forkserver`: Fuzzers using a forkserver-style executor.
- `full-system`: Fuzzers for full-system targets (kernels, firmwares, etc...).
- `fuzzbench`: Fuzzbench fuzzers.
- `grammar-aware`: Grammar-aware fuzzers.
- `inprocess`: In-process fuzzers, whn they don't fit another more specific type.
- `others`: Fuzzers for specific / specialized things, that do not go in a specific category.

## Paper Artifacts

Multiple papers based on LibAFL have been published and include artifacts.
Here is a list of LibAFL artifacts:

- Fuzzbench implementation: https://github.com/AFLplusplus/libafl_fuzzbench
- LibAFL QEMU experiments: https://github.com/AFLplusplus/libafl_qemu_artifacts
