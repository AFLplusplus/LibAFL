# Crates

LibAFL is composed by different crates.
Each one has its self-contained purpose, and the user may not need to use all of them in its project.

Following the naming convention of the folders in the project's root, they are:

### libafl

This is the main crate that contains all the components needed to build a fuzzer.

This crate has the following feature flags:

- std, that enables the parts of the code that use the Rust standard library. Without this flag, libafl is no_std.
- derive, that enables the usage of the `derive(...)` macros defined in libafl_derive from libafl.

By default, std and derive are both set.

### libafl_derive

This a proc-macro crate paired with the libafl crate.

At the moment, it just expose the `derive(SerdeAny)` macro that can be used to define metadata structs.

### libafl_targets

This crate that exposes, under feature flags, pieces of code to interact with targets

Currently, the supported flags are:

- pcguard_edges, that defines the SanitizerCoverage trace-pc-guard hooks to track the executed edges in a map.
- pcguard_hitcounts, that defines the SanitizerCoverage trace-pc-guard hooks to track the executed edges with the hitcounts (like AFL) in a map.
- libfuzzer, that expose a compatibility layer with libFuzzer style harnesses.
- value_profile, that defines the SanitizerCoverage trace-cmp hooks to track the matching bits of each comparison in a map. 

### libafl_cc

This is a library that provides some utils to wrap compilers and create source level fuzzers.

At the moment, only the Clang compiler is supported.

### libafl_frida

This library bridges libafl with Frida as instrumentation backend.

With this crate you can instrument targets on Linux/macOS/Windows/Android for coverage collection.

The CmpLog and AddressSanitizer instrumentation and runtimes are currently supported only for ARM64.

### libafl_qemu

This library bridges libafl with QEMU user-mode to fuzz ELF binaries.

It works on Linux and can collect edge coverage withotu collisions.
