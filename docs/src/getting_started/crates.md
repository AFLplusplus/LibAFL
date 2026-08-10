# Crates

LibAFL is composed of different crates.
A crate is an individual library in Rust's Cargo build system, that you can use by adding it to your project's `Cargo.toml`, like:

```toml
[dependencies]
libafl = { version = "*" }
```

## Crate List

For LibAFL, each crate has its self-contained purpose, and the user may not need to use all of them in their project.
Following the structure of [`crates/README.md`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/README.md), the crates are organized into the following categories:

---

## Core Crates

### [`libafl`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl)

This is the main crate that contains all the components needed to build a fuzzer.

This crate has a number of feature flags that enable and disable certain aspects of LibAFL.
The features can be found in [LibAFL's `Cargo.toml`](https://github.com/AFLplusplus/LibAFL/blob/main/crates/libafl/Cargo.toml) under "`[features]`", and are usually explained with comments there.
Some features worthy of remark are:

- `std` enables the parts of the code that use the Rust standard library. Without this flag, LibAFL is `no_std` compatible. This disables a range of features, but allows us to use LibAFL in embedded environments, read [the `no_std` section](../advanced_features/no_std.md) for further details.
- `derive` enables the usage of the `derive(...)` macros defined in libafl_derive from libafl.
- `rand_trait` allows you to use LibAFL's very fast (*but insecure!*) random number generator wherever compatibility with Rust's [`rand` crate](https://crates.io/crates/rand) is needed.
- `llmp_bind_public` makes LibAFL's LLMP bind to a public TCP port, over which other fuzzers nodes can communicate with this instance.
- `introspection` adds performance statistics to LibAFL.

You can choose the features by using `features = ["feature1", "feature2", ...]` for LibAFL in your `Cargo.toml`.
Out of this list, by default, `std`, `derive`, and `rand_trait` are already set.
You can choose to disable them by setting `default-features = false` in your `Cargo.toml`.

### [`libafl_bolts`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_bolts)

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

### [`libafl_sugar`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_sugar)

The sugar crate abstracts away most of the complexity of LibAFL's API.
Instead of high flexibility, it aims to be high-level and easy-to-use.
It is not as flexible as stitching your fuzzer together from each individual component, but allows you to build a fuzzer with minimal lines of code.
To see it in action, take a look at the [`libfuzzer_stb_image_sugar` example fuzzer](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/inprocess/libfuzzer_stb_image_sugar).

### [`libafl_targets`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_targets)

This crate exposes code to interact with, and to instrument, targets.
To enable and disable features at compile-time, the features are enabled and disabled using feature flags.

Currently, the supported flags are:

- `pcguard_edges` defines the SanitizerCoverage trace-pc-guard hooks to track the executed edges in a map.
- `pcguard_hitcounts` defines the SanitizerCoverage trace-pc-guard hooks to track the executed edges with the hitcounts (like AFL) in a map.
- `libfuzzer` exposes a compatibility layer with libFuzzer style harnesses.
- `value_profile` defines the SanitizerCoverage trace-cmp hooks to track the matching bits of each comparison in a map.

---

## Backends & Instrumentation

### [`libafl_frida`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_frida)

This library bridges LibAFL with Frida as instrumentation backend.
With this crate, you can instrument targets on Linux/macOS/Windows/Android for coverage collection.
Additionally, it supports CmpLog, and AddressSanitizer instrumentation and runtimes for aarch64.
See further information, as well as usage instructions, [later in the book](../advanced_features/frida.md).

### [`libafl_intelpt`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_intelpt)

An Intel Processor Trace (Intel PT) wrapper library for LibAFL. It enables hardware-assisted tracing and coverage collection for binary targets on Linux and Windows.

### [`libafl_nyx`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_nyx)

[Nyx](https://nyx-fuzz.com/) is a KVM-based snapshot fuzzer. `libafl_nyx` adds these capabilities to LibAFL. There is a specific section explaining usage of libafl_nyx [later in the book](../advanced_features/nyx.md).

### [`libafl_qemu`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_qemu)

This library bridges LibAFL with QEMU user-mode to fuzz ELF cross-platform binaries.

It works on Linux and can collect edge coverage without collisions!
It also supports a wide range of hooks and instrumentation options.

### [`libafl_tinyinst`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_tinyinst)

This library bridges LibAFL with [TinyInst](https://github.com/googleprojectzero/tinyinst) as a lightweight dynamic instrumentation backend for black-box fuzzing on macOS and Windows.

### [`libafl_unicorn`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_unicorn)

This library bridges LibAFL with the Unicorn CPU emulator framework for emulated target execution and coverage collection.

---

## Compatibility & Integration

### [`libafl_cc`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_cc)

This is a library that provides utils to wrap compilers and create source-level fuzzers.

At the moment, only the Clang compiler is supported.
To understand it deeper, look through the tutorials and examples.

### [`libafl_libfuzzer`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_libfuzzer)

A libFuzzer shim which uses LibAFL with common defaults to allow running existing libFuzzer targets using LibAFL's engine.

### [`libafl_libfuzzer_runtime`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_libfuzzer_runtime)

Runtime library providing execution and context tracking for LibAFL's libFuzzer compatibility layer.

---

## Utility & Infrastructure Crates

In addition to the primary crates above, LibAFL includes specialized utility crates (many of which were decoupled from `libafl_bolts` internals):

- **[`libafl_core`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_core)**: Minimal set of core functions and types shared across LibAFL crates.
- **[`libafl_derive`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_derive)**: Proc-macro crate providing derive implementations like `derive(SerdeAny)` for Metadata structs (see [Metadata](../design/metadata.md)).
- **[`libafl_asan`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/libafl_asan)**: AddressSanitizer helper library for memory error detection integration.
- **[`build_id2`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/build_id2)**: Updated build ID extraction library for binary targets.
- **[`core_affinity2`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/core_affinity2)**: Cross-platform thread/core affinity management.
- **[`exceptional`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/exceptional)**: Exception and signal handling primitives.
- **[`fast_rands`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/fast_rands)**: Non-cryptographic, high-performance pseudo-random number generators.
- **[`ll_mp`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/ll_mp)**: Low Level Message Passing (LLMP) lock-free IPC implementation.
- **[`minibsod`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/minibsod)**: Crash signal, register state, and mini crash report dumping.
- **[`no_std_time`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/no_std_time)**: High-resolution time measurement utilities compatible with `no_std` environments.
- **[`ownedref`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/ownedref)**: Smart reference wrapper that deserializes into owned values.
- **[`serde_anymap`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/serde_anymap)**: Any-map implementation that supports serialization and deserialization via Serde.
- **[`shmem_providers`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/shmem_providers)**: Cross-platform shared memory implementations (Linux, Windows, Android, iOS).
- **[`tuple_list_ex`](https://github.com/AFLplusplus/LibAFL/tree/main/crates/tuple_list_ex)**: Functional extensions for compile-time tuple lists.

