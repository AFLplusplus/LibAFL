# Introduction

Fuzzers are important tools for security researchers and developers alike.
A wide range of state-of-the-art tools like [AFL++](https://github.com/AFLplusplus/AFLplusplus), [libFuzzer](https://llvm.org/docs/LibFuzzer.html) or [honggfuzz](https://github.com/google/honggfuzz) are available to users. They do their job in a very effective way, finding thousands of bugs.

From the perspective of a power user, however, these tools are limited.
Their designs do not treat extensibility as a first-class citizen.
Usually, a fuzzer developer can choose to either fork one of these existing tools, or to create a new fuzzer from scratch.
In any case, researchers end up with tons of fuzzers, all of which are incompatible with each other.
Their outstanding features cannot just be combined for new projects.
By reinventing the wheel over and over, we may completely miss out on features that are complex to reimplement.

To tackle this issue, we created LibAFL, a library that is _not just another fuzzer_, but a collection of reusable pieces for individual fuzzers.
LibAFL, written in Rust, helps you develop a fuzzer tailored for your specific needs.
Be it a specific target, a particular instrumentation backend, or a custom mutator, you can leverage existing bits and pieces to craft the fastest and most efficient fuzzer you can envision.

## Why LibAFL?

LibAFL gives you many of the benefits of an off-the-shelf fuzzer, while being completely customizable.
Some highlight features currently include:

- `multi platform`: LibAFL works pretty much anywhere you can find a Rust compiler for. We already used it on *Windows*, *Android*, *MacOS*, and *Linux*, on *x86_64*, *aarch64*, ...
- `portable`: `LibAFL` can be built in `no_std` mode.
This means it does not require a specific OS-dependent runtime to function.
Define an allocator and a way to map pages, and you are good to inject LibAFL in obscure targets like embedded devices, hypervisors, or maybe even WebAssembly?
- `adaptable`: Given years of experience fine-tuning *AFLplusplus* and our academic fuzzing background, we could incorporate recent fuzzing trends into LibAFL's design and make it future-proof.
To give an example, as opposed to old-school fuzzers, a `BytesInput` is just one of the potential forms of inputs:
feel free to use and mutate an Abstract Syntax Tree instead, for structured fuzzing.
- `scalable`: As part of LibAFL, we developed `Low Level Message Passing`, `LLMP` for short, which allows LibAFL to scale almost linearly over cores. That is, if you chose to use this feature - it is your fuzzer, after all.
Scaling to multiple machines over TCP is also possible, using LLMP's `broker2broker` feature.
- `fast`: We do everything we can at compile time so that the runtime overhead is as minimal as it can get.
- `bring your own target`: We support binary-only modes, like (full-system) QEMU-Mode and Frida-Mode with ASan and CmpLog, as well as multiple compilation passes for sourced-based instrumentation.
Of course, we also support custom instrumentation, as you can see in the Python example based on Google's Atheris.
- `usable`: This one is on you to decide. Dig right in!
