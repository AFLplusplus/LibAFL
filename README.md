# LibAFL, the fuzzer library.

 <img align="right" src="https://raw.githubusercontent.com/AFLplusplus/Website/main/static/libafl_logo.svg" alt="LibAFL logo" width="250" heigh="250">

Advanced Fuzzing Library - Slot your own fuzzers together and extend their features using Rust.

LibAFL is written and maintained by

 * [Andrea Fioraldi](https://twitter.com/andreafioraldi) <andrea@aflplus.plus>
 * [Dominik Maier](https://twitter.com/domenuk) <dominik@aflplus.plus>
 * [s1341](https://twitter.com/srubenst1341) <github@shmarya.net>
 * [Dongjia Zhang](https://github.com/tokatoka) <toka@aflplus.plus>

## Why LibAFL?

LibAFL gives you many of the benefits of an off-the-shelf fuzzer, while being completely customizable.
Some highlight features currently include:
- `fast`: We do everything we can at compile time, keeping runtime overhead minimal. Users reach 120k execs/sec in frida-mode on a phone (using all cores).
- `scalable`: `Low Level Message Passing`, `LLMP` for short, allows LibAFL to scale almost linearly over cores, and via TCP to multiple machines.
- `adaptable`: You can replace each part of LibAFL. For example, `BytesInput` is just one potential form input:
feel free to add an AST-based input for structured fuzzing, and more.
- `multi platform`: LibAFL was confirmed to work on *Windows*, *MacOS*, *Linux*, and *Android* on *x86_64* and *aarch64*. `LibAFL` can be built in `no_std` mode to inject LibAFL into obscure targets like embedded devices and hypervisors.
- `bring your own target`: We support binary-only modes, like Frida-Mode, as well as multiple compilation passes for sourced-based instrumentation. Of course it's easy to add custom instrumentation backends.

## Overview

LibAFL is a collection of reusable pieces of fuzzers, written in Rust.
It is fast, multi-platform, no_std compatible, and scales over cores and machines.

It offers a main crate that provide building blocks for custom fuzzers, [libafl](./libafl), a library containing common code that can be used for targets instrumentation, [libafl_targets](./libafl_targets), and a library providing facilities to wrap compilers, [libafl_cc](./libafl_cc).

LibAFL offers integrations with popular instrumentation frameworks. At the moment, the supported backends are:

+ SanitizerCoverage, in [libafl_targets](./libafl_targets)
+ Frida, in [libafl_frida](./libafl_frida)
+ QEMU user-mode, in [libafl_qemu](./libafl_qemu)
+ TinyInst, in [libafl_tinyinst](./libafl_tinyinst) by [elbiazo](https://github.com/elbiazo)

## Getting started

1. Install the Dependecies
- The Rust development language.  
We highly recommend *not* to use e.g. your Linux distribition package as this is likely outdated. So rather install
Rust directly, instructions can be found [here](https://www.rust-lang.org/tools/install).

- LLVM tools  
The LLVM tools are needed (newer than LLVM 11.0.0 but older than LLVM 15.0.0)

- Cargo-make  
We use cargo-make to build the fuzzers in `fuzzers/` directory. You can install it with

```
cargo install cargo-make
```

2. Clone the LibAFL repository with

```
git clone https://github.com/AFLplusplus/LibAFL
```

3. Build the library using

```
cargo build --release
```

4. Build the API documentation with

```
cargo doc
```

5. Browse the LibAFL book (WIP!) with (requires [mdbook](https://github.com/rust-lang/mdBook))

```
cd docs && mdbook serve
```

We collect all example fuzzers in [`./fuzzers`](./fuzzers/).
Be sure to read their documentation (and source), this is *the natural way to get started!*

You can run each example fuzzer with
```
cargo make run
```
as long as the fuzzer directory has `Makefile.toml` file.

The best-tested fuzzer is [`./fuzzers/libfuzzer_libpng`](./fuzzers/libfuzzer_libpng), a multicore libfuzzer-like fuzzer using LibAFL for a libpng harness.

## Resources

+ [Installation guide](./docs/src/getting_started/setup.md)

+ [Online API documentation](https://docs.rs/libafl/)

+ The LibAFL book (WIP) [online](https://aflplus.plus/libafl-book) or in the [repo](./docs/src/)

+ Our research [paper](https://www.s3.eurecom.fr/docs/ccs22_fioraldi.pdf)

+ Our RC3 [talk](http://www.youtube.com/watch?v=3RWkT1Q5IV0 "Fuzzers Like LEGO") explaining the core concepts

+ Our Fuzzcon Europe [talk](https://www.youtube.com/watch?v=PWB8GIhFAaI "LibAFL: The Advanced Fuzzing Library") with a (a bit but not so much outdated) step-by-step discussion on how to build some example fuzzers

+ The Fuzzing101 [solutions](https://github.com/epi052/fuzzing-101-solutions) & series of [blog posts](https://epi052.gitlab.io/notes-to-self/blog/2021-11-01-fuzzing-101-with-libafl/) by [epi](https://github.com/epi052)

+ Blogpost on binary-only fuzzing lib libaf_qemu, [Hacking TMNF - Fuzzing the game server](https://blog.bricked.tech/posts/tmnf/part1/), by [RickdeJager](https://github.com/RickdeJager).

## Contributing

For bugs, feel free to open issues or contact us directly. Thank you for your support. <3

Even though we will gladly assist you in finishing up your PR, try to
- keep all the crates compiling with *stable* rust (hide the eventual non-stable code under [`cfg`s](https://github.com/AFLplusplus/LibAFL/blob/main/libafl/build.rs#L26))
- run `cargo fmt` on your code before pushing
- check the output of `cargo clippy --all` or `./clippy.sh`
- run `cargo build --no-default-features` to check for `no_std` compatibility (and possibly add `#[cfg(feature = "std")]`) to hide parts of your code.

Some of the parts in this list may be hard, don't be afraid to open a PR if you cannot fix them by yourself, so we can help.

## Cite

If you use LibAFL for your academic work, please cite the following paper:

```bibtex
@inproceedings{libafl,
 author       = {Andrea Fioraldi and Dominik Maier and Dongjia Zhang and Davide Balzarotti},
 title        = {{LibAFL: A Framework to Build Modular and Reusable Fuzzers}},
 booktitle    = {Proceedings of the 29th ACM conference on Computer and communications security (CCS)},
 series       = {CCS '22},
 year         = {2022},
 month        = {November},
 location     = {Los Angeles, U.S.A.},
 publisher    = {ACM},
}
```

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>

<br>

<sub>
Dependencies under more restrictive licenses, such as GPL or AGPL, can be enabled
using the respective feature in each crate when it is present, such as the
'agpl' feature of the libafl crate.
</sub>
