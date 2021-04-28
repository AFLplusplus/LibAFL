# LibAFL, the fuzzer library.

Advanced Fuzzing Library - Slot your own fuzzers together and extend their features using Rust.

LibAFL is written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com> and Dominik Maier <mail@dmnk.co>.

## What

LibAFL is a collection of reusable pieces of fuzzers, written in Rust.

It offers a main crate that provide building blocks for custom fuzzers, [libafl](./libafl), a library containing common code that can be used for targets instrumentation, [libafl_targets](./libafl_targets), and a library providing facilities to wrap compilers, [libafl_cc](./libafl_cc).

LibAFL is fast, multi-platform, no_std compatible, and scales over cores (and machines in the near future!).

LibAFL offers integrations with popular instrumemntation frameworks too. At the moment, the supported backends are:

+ SanitizerCoverage, in [libafl_targets](./libafl_targets)
+ Frida, in [libafl_frida](./libafl_frida), by s1341 <github@shmarya.net> (Windows support will be added soon)

## Getting started

Clone the LibAFL repository with

```
git clone https://github.com/AFLplusplus/LibAFL
```

Build the library using

```
cargo build --release
```

Build the API documentation with

```
cargo doc
```

Browse the LibAFL book with (requires [mdbook](https://github.com/rust-lang/mdBook))

```
cd docs && mdbook serve
```

We collect example fuzzers in [`./fuzzers`](./fuzzers/).

The best-tested fuzzer is [`./fuzzers/libfuzzer_libpng`](./fuzzers/libfuzzer_libpng), a multicore libfuzzer-like fuzzer using LibAFL for a libpng harness.

## Resources

+ [Installation guide](./docs/src/getting_started/setup.md)

+ Our RC3 [talk](http://www.youtube.com/watch?v=3RWkT1Q5IV0 "Fuzzers Like LEGO") explaining the core concepts

+ [Online API documentation](https://docs.rs/libafl/)

+ The LibAFL book (very WIP) [online](https://aflplus.plus/libafl-book) or in the [repo](./docs/src/)

## Contributing

Check the [TODO.md](./TODO.md) file for features that we plan to support.

For bugs, feel free to open issues or contact us directly. Thank you for your support. <3

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

