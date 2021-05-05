# Introduction

Fuzzers are important assets in the pockets of security researchers and developers alike.
A wide range of cool state-of-the-art tools like [AFL++](https://github.com/AFLplusplus/AFLplusplus), [libFuzzer](https://llvm.org/docs/LibFuzzer.html) or [honggfuzz](https://github.com/google/honggfuzz) are available to users. They do their job in a very effective way, finding thousands of bugs.

From the power user perspective, however, these tools are limited.
Their design does not treat extensibility as a first-class citizen.
Usually, a fuzzer developer can choose to either fork one of these existing tools, or to create a new fuzzer from scratch.
In any case, researchers end up with tons of fuzzers, all of which are incompatible with each other.
Their outstanding features can not just be combined for new projects.
Instead, we keep reinventing the wheel and may completely miss out on features that are complex to reimplement.

Here comes LibAFL, a library that IS NOT a fuzzer, but a collection of reusable pieces of fuzzers, written in Rust.
LibAFL helps you develop your own custom fuzzer, tailored for your specific needs.
Be it a specific target, a particular instrumentation backend, or a custom mutator, you can leverage existing bits and pieces to craft the fastest and most efficient fuzzer you can envision.

## Why LibAFL?

LibAFL gives you many of the benefits of an off-the-shelf fuzzer, while being completely customizable.
Some highlight features currently include:
- `multi platform`: LibAFL works pretty much anywhere you can find a Rust compiler for. We already used it on *Windows*, *Android*, *MacOS*, and *Linux*, on *x86_64*, *aarch64*, ...
- `portable`: `LibAFL` can be built in `no_std` mode. This means it does not require a specific OS-dependent runtime to function. Define an allocator and a way to map pages, you should be good to inject LibAFL in obscure targets like embedded devices, hypervisors, or maybe even WebAssembly?
- `adaptable`: Given year of experience fine-tuning *AFLplusplus* and our academic fuzzing background, we could incorporate recent fuzzing trends into LibAFL's deign and make it future-proof.
To give an example, as opposed to old-skool fuzzers, a `BytesInput` is just one of the potential forms of inputs:
feel free to use and mutate an Abstract Syntax Tree instead, for structured fuzzing.
- `scalable`: As part of LibAFL, we developed `Low Level Message Passing`, `LLMP` for short, which allows LibAFL to scale almost linearly over cores. That is, if you chose to use this feature - it is your fuzzer, after all. Scaling to multiple machines over TCP is on the near road-map.
- `fast`: We do everything we can at compiletime so that the runtime overhead is as minimal as it can get.
- `bring your own target`: We support binary-only modes, like Frida-Mode with ASAN and CmpLog, as well as multiple compilation passes for sourced-based instrumentation, and of course support custom instrumentation.
- `usable`: This one is on you to decide. Dig right in!