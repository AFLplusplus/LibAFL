# Setup Guide

This guide will help you install and set up LibAFL on your system.

## Install the Dependencies

### The Rust development language

- We highly recommend *not* to use e.g. your Linux distribution package as this is likely outdated. So rather install Rust directly, instructions can be found [here](https://www.rust-lang.org/tools/install).
- The minimum supported Rust version is defined. You can always check the currently required version in LibAFL's [Cargo.toml](https://github.com/AFLplusplus/LibAFL/blob/main/crates/libafl/Cargo.toml):

  If your installed Rust version is older than the one listed in Cargo.toml, update to the latest stable toolchain:

  ```bash
  rustup update stable
  ```

### LLVM tools

- The LLVM tools (including clang, clang++) are needed (newer than LLVM 15.0.0 up to LLVM 18.1.3) If you are using Debian/Ubuntu, again, we highly recommmend that you install the package from [here](https://apt.llvm.org/)
- (In `libafl_concolic`, we only support LLVM version newer than 18)

### Just

- We use [just](https://github.com/casey/just) to build the fuzzers in `fuzzers/` directory. You can find instructions to install it in your environment [in the Just Programmer's Manual](https://just.systems/man/en/packages.html).

## Installation Steps

### Clone the `LibAFL` repository

```sh
git clone https://github.com/AFLplusplus/LibAFL
```

### Build the library

```sh
cargo build --release
```

### Build the API documentation

```sh
cargo doc
```

### Browse the `LibAFL` book (WIP!)

Requires [mdbook](https://rust-lang.github.io/mdBook/index.html):

```sh
cd docs && mdbook serve
```

## Getting Started

We collect all example fuzzers in [`./fuzzers`](./fuzzers/).
Be sure to read their documentation (and source), this is *the natural way to get started!*

```sh
just run
```

You can run each example fuzzer with this following command, as long as the fuzzer directory has a `Justfile` file. The best-tested fuzzer is [`./fuzzers/inprocess/libfuzzer_libpng`](./fuzzers/inprocess/libfuzzer_libpng), a multicore libfuzzer-like fuzzer using `LibAFL` for a libpng harness.

## Additional Resources

- [Online API documentation](https://docs.rs/libafl/)
- The `LibAFL` book (WIP) [online](https://aflplus.plus/libafl-book) or in the [repo](./docs/src/)
- Our research [paper](https://www.s3.eurecom.fr/docs/ccs22_fioraldi.pdf)
- Our RC3 [talk](http://www.youtube.com/watch?v=3RWkT1Q5IV0 "Fuzzers Like LEGO") explaining the core concepts
- Our Fuzzcon Europe [talk](https://www.youtube.com/watch?v=PWB8GIhFAaI "LibAFL: The Advanced Fuzzing Library") with a (a bit but not so much outdated) step-by-step discussion on how to build some example fuzzers
- The Fuzzing101 [solutions](https://github.com/epi052/fuzzing-101-solutions) & series of [blog posts](https://epi052.gitlab.io/notes-to-self/blog/2021-11-01-fuzzing-101-with-libafl/) by [epi](https://github.com/epi052)
- Blogpost on binary-only fuzzing lib `libaf_qemu`, [Hacking TMNF - Fuzzing the game server](https://blog.bricked.tech/posts/tmnf/part1/), by [RickdeJager](https://github.com/RickdeJager).
- [A LibAFL Introductory Workshop](https://www.atredis.com/blog/2023/12/4/a-libafl-introductory-workshop), by [Jordan Whitehead](https://github.com/jordan9001)
