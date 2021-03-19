# LibAFL, the fuzzer library.

Advanced Fuzzing Library - Slot your own fuzzers together and extend their features using Rust.

LibAFL is written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com> and Dominik Maier <mail@dmnk.co>.

It is released as Open Source Software under the [Apache v2](LICENSE-APACHE) or [MIT](LICENSE-MIT) licenses.

## Getting started

Clone the LibAFL repository with

```
git clone https://github.com/AFLplusplus/LibAFL
```

Build the library using

```
cargo build --release
```

Build the documentation with

```
cargo doc
```

We collect example fuzzers in `./fuzzers`. They can be build using `cargo build --example [fuzzer_name] --release`.

The best-tested fuzzer is `./fuzzers/libfuzzer_libpng`, a clone of libfuzzer using libafl for a libpng harness.
See its readme [here](./fuzzers/libfuzzer_libpng/README.md).

## The Core Concepts

The entire library is based on some core concepts that we think can generalize Fuzz Testing.

We're still working on extending the documentation.

In the meantime, you can watch the Video from last year's RC3, here:

[![Video explaining libAFL's core concepts](http://img.youtube.com/vi/3RWkT1Q5IV0/3.jpg)](http://www.youtube.com/watch?v=3RWkT1Q5IV0 "Fuzzers Like LEGO")

## Contributing

Check the [TODO.md](./TODO.md) file for features that we plan to support.

For bugs, feel free to open issues or contact us directly. Thank you for your support. <3
