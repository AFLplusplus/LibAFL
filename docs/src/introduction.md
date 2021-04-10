# Introduction

Fuzzers are important assets in the pockets of security researchers and even developers nowadays.
A wide range of cool state-of-the-art tools like [AFL++](https://github.com/AFLplusplus/AFLplusplus), [libFuzzer](https://llvm.org/docs/LibFuzzer.html) or [honggfuzz](https://github.com/google/honggfuzz) are avaiable to users and they do their job in a very effective way.

From the power user perspective, however, these tools are limited because not designed with the extensibility as first-class citizen.
Usually, a fuzzer developer has to choose if fork one of these existing tools with the result of having a tons of fuzzers derived from others which are in any case incompatible with each other, or creating a new fuzzer from scratch, reinventing the wheel and usually giving up on features that are complex to reimplement.

Here comes LibAFL, a library that IS NOT a fuzzer, but a collection of reusable pieces of fuzzers written in Rust.
LibAFL helps you writing your own custom fuzzer, tailored for a specific target or for a particular instrumentation backend, without reinventing the wheel or forking an existing fuzzer.

## Why you should use LibAFL

TODO list here killer features (no_std, multi platform, scalability, ...)
