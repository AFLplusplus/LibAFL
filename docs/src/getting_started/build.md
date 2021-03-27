# Build

LibAFL, as most of the Rust projects, can be built using `cargo` from the root directory of the project with:

```sh
$ cargo build --release
```

Note that the `--release` flag is optional for development, but it is needed for fuzzing at a decent speed,
otherwise you will experience a slowdown of even more than 10x.

The LibAFL repository is composed by multiple crates, and the top-level Cargo.toml is just an orchestrator that groups these crates
in a workspace. Building from the root directory will build all the crates in the workspace.

## Build example fuzzers

You can notice that in the repository there is a `fuzzers/` folder.
This folder contains a set of crates that are not part of the workspace, so that are not built issuing `cargo build` from the top-level directory.

These crates are examples of fuzzers using particular features of LibAFL combined sometimes with instrumentation backends (e.g. [SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html), [Frida](https://frida.re/), ...).

The user can use these crates as examples and as skeleton for its custom fuzzer using a similar set of features.

To build an example fuzzer you have to invoke cargo from its folder (`fuzzers/[FUZZER_NAME]).
