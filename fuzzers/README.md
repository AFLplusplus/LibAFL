# LibAFL Fuzzers

## Example fuzzers

You can find here all the example fuzzers built on top of LibAFL.
They are sorted by focus:

- `baby`: Minimal fuzzers and fuzzers demonstrating specific features that don't fit anywhere else.
- `inprocess`: Common In-process fuzzers. Most of the time, this is what you want.
- `binary_only`: Fuzzers for binary-only targets.
- `forkserver`: Fuzzers that use a forkserver-style executor.
- `full_system`: Fuzzers for full-system targets (kernels, firmwares, etc...).
- `fuzzbench`: Fuzzbench fuzzers.
- `structure_aware`: Grammar fuzzers, fuzzers for certain languages, fuzzers with custom inputs, and more.
- `fuzz-anything`: Fuzzers for advanced targets like WASM or python, and other fuzzers that can be used for anything.

(Some fuzzers may fit into multiple categories, in which case we sort them as it makes sense, for example `structure_aware > full_system > binary_only > the rest`)

Some rather complete fuzzers worth looking at are:

- [`fuzzbench`](./inprocess/fuzzbench/): Our fuzzer that competes in Fuzzbench
- [`LibAFL-fuzz`](./forkserver/libafl-fuzz/): A reimplementation of afl-fuzz, the traditional forkserver fuzzer that tries to emulate the command line and behavior.
- [`LibAFL-QEMU-Launcher`](./binary_only/qemu_launcher/): A full-featured QEMU-mode fuzzer that runs on multiple cores

## Paper Artifacts

Multiple papers based on LibAFL have been published and include artifacts.
Here is a list of LibAFL artifacts:

- Fuzzbench implementation: https://github.com/AFLplusplus/libafl_fuzzbench
- LibAFL QEMU experiments: https://github.com/AFLplusplus/libafl_qemu_artifacts
