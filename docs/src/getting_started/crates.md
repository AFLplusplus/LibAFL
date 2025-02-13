# Crates

LibAFL is composed of different crates.
A crate is an individual library in Rust's Cargo build system, that you can use by adding it to your project's `Cargo.toml`, like:

```toml
[dependencies]
libafl = { version = "*" }
```

## Crate List

For LibAFL, each crate has its self-contained purpose, and the user may not need to use all of them in their project.
Following the naming convention of the folders in the project's root, they are:

### [`libafl`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl)

This is the main crate that contains all the components needed to build a fuzzer.

This crate has a number of feature flags that enable and disable certain aspects of LibAFL.
The features can be found in [LibAFL's `Cargo.toml`](https://github.com/AFLplusplus/LibAFL/blob/main/libafl/Cargo.toml) under "`[features]`", and are usually explained with comments there.
Some features worthy of remark are:

- `std` enables the parts of the code that use the Rust standard library. Without this flag, LibAFL is `no_std` compatible. This disables a range of features, but allows us to use LibAFL in embedded environments, read [the `no_std` section](../advanced_features/no_std.md) for further details.
- `derive` enables the usage of the `derive(...)` macros defined in libafl_derive from libafl.
- `rand_trait` allows you to use LibAFL's very fast (*but insecure!*) random number generator wherever compatibility with Rust's [`rand` crate](https://crates.io/crates/rand) is needed.
- `llmp_bind_public` makes LibAFL's LLMP bind to a public TCP port, over which other fuzzers nodes can communicate with this instance.
- `introspection` adds performance statistics to LibAFL.

You can choose the features by using `features = ["feature1", "feature2", ...]` for LibAFL in your `Cargo.toml`.
Out of this list, by default, `std`, `derive`, and `rand_trait` are already set.
You can choose to disable them by setting `default-features = false` in your `Cargo.toml`.

### [`libafl_bolts`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_bolts)

The `libafl_bolts` crate is a minimal tool shed filled with useful low-level rust features, not necessarily related to fuzzers.
In it, you'll find highlights like:

- `core_affinity` to bind the current process to cores
- `SerdeAnyMap` a map that can store typed values in a serializable fashion
- `minibsod` to dump the current process state
- `LLMP`, "low level message passing", a lock-free IPC mechanism
- `Rand`, different fast (non-cryptographically secure) RNG implementations like RomuRand
- `ShMem`, a platform independent shard memory implementation
- `Tuples`, a compiletime tuple implementation

... and much more.

### [`libafl_sugar`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_sugar)

The sugar crate abstracts away most of the complexity of LibAFL's API.
Instead of high flexibility, it aims to be high-level and easy-to-use.
It is not as flexible as stitching your fuzzer together from each individual component, but allows you to build a fuzzer with minimal lines of code.
To see it in action, take a look at the [`libfuzzer_stb_image_sugar` example fuzzer](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/inprocess/libfuzzer_stb_image_sugar).

### [`libafl_derive`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_derive)

This a proc-macro crate paired with the `libafl` crate.

At the moment, it just exposes the `derive(SerdeAny)` macro that can be used to define Metadata structs, see the section about [Metadata](../design/metadata.md) for details.

### [`libafl_targets`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_targets)

This crate exposes code to interact with, and to instrument, targets.
To enable and disable features at compile-time, the features are enabled and disabled using feature flags.

Currently, the supported flags are:

- `pcguard_edges` defines the SanitizerCoverage trace-pc-guard hooks to track the executed edges in a map.
- `pcguard_hitcounts` defines the SanitizerCoverage trace-pc-guard hooks to track the executed edges with the hitcounts (like AFL) in a map.
- `libfuzzer` exposes a compatibility layer with libFuzzer style harnesses.
- `value_profile` defines the SanitizerCoverage trace-cmp hooks to track the matching bits of each comparison in a map.

### [`libafl_cc`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_cc)

This is a library that provides utils to wrap compilers and create source-level fuzzers.

At the moment, only the Clang compiler is supported.
To understand it deeper, look through the tutorials and examples.

### [`libafl_frida`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_frida)

This library bridges LibAFL with Frida as instrumentation backend.
With this crate, you can instrument targets on Linux/macOS/Windows/Android for coverage collection.
Additionally, it supports CmpLog, and AddressSanitizer instrumentation and runtimes for aarch64.
See further information, as well as usage instructions, [later in the book](../advanced_features/frida.md).

### [`libafl_qemu`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_qemu)

This library bridges LibAFL with QEMU user-mode to fuzz ELF cross-platform binaries.

It works on Linux and can collect edge coverage without collisions!
It also supports a wide range of hooks and instrumentation options.

### [`libafl_nyx`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_nyx)

[Nyx](https://nyx-fuzz.com/) is a KVM-based snapshot fuzzer. `libafl_nyx` adds these capabilities to LibAFL. There is a specific section explaining usage of libafl_nyx [later in the book](../advanced_features/nyx.md).

### [`libafl_concolic`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_concolic)

Concolic fuzzing is the combination of fuzzing and a symbolic execution engine.
This can reach greater depth than normal fuzzing, and is exposed in this crate.
There is a specific section explaining usage of libafl_concolic [later in the book](../advanced_features/concolic.md).
