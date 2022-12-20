# Building LibAFL

LibAFL, as most of the Rust projects, can be built using `cargo` from the root directory of the project with:

```sh
$ cargo build --release
```

Note that the `--release` flag is optional for development, but you need to add it to do fuzzing at a decent speed.
Slowdowns of 10x or more are not uncommon for Debug builds.

The LibAFL repository is composed of multiple crates.
The [top-level `Cargo.toml`](https://github.com/AFLplusplus/LibAFL/blob/main/Cargo.toml) is the workspace file grouping these crates.
Calling `cargo build` from the root directory will compile all crates in the workspace.

## Build Example Fuzzers

The best starting point for experienced rustaceans is to read through, and adapt, the example fuzzers.

We group these fuzzers in the [`./fuzzers`](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers) directory of the LibAFL repository.
The directory contains a set of crates that are not part of the workspace.

Each of these example fuzzers uses particular features of LibAFL, sometimes combined with different instrumentation backends (e.g. [SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html), [Frida](https://frida.re/), ...).

You can use these crates as examples and as skeletons for custom fuzzers with similar feature sets.
Each fuzzer will have a `README.md` file in its directory, describing the fuzzer and its features.

To build an example fuzzer, you have to invoke `cargo build --release` from its respective folder (`fuzzers/[FUZZER_NAME]`).
