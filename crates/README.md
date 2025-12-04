# LibAFL Crates

This directory contains the various crates that make up the LibAFL ecosystem. Here is a brief overview of each:

## Core Crates

- **[libafl](./libafl)**: Slot your own fuzzers together and extend their features using Rust. The main crate.
- **[libafl_bolts](./libafl_bolts)**: Low-level bolts to create fuzzers and so much more.
- **[libafl_sugar](./libafl_sugar)**: Sugar builders to create common fuzzers with LibAFL.
- **[libafl_targets](./libafl_targets)**: Common code for target instrumentation that can be used combined with LibAFL.

## Backends & Instrumentation

- **[libafl_concolic](./libafl_concolic)**: Concolic execution related crates (SymCC integration).
- **[libafl_frida](./libafl_frida)**: Frida backend library for LibAFL.
- **[libafl_intelpt](./libafl_intelpt)**: Intel Processor Trace wrapper for libafl.
- **[libafl_nyx](./libafl_nyx)**: libafl using nyx, only avaliable on linux.
- **[libafl_qemu](./libafl_qemu)**: QEMU user backend library for LibAFL.
- **[libafl_tinyinst](./libafl_tinyinst)**: TinyInst backend for libafl.
- **[libafl_unicorn](./libafl_unicorn)**: Unicorn backend library for LibAFL.

## Compatibility & Integration

- **[libafl_cc](./libafl_cc)**: Commodity library to wrap compilers and link LibAFL.
- **[libafl_libfuzzer](./libafl_libfuzzer)**: libFuzzer shim which uses LibAFL with common defaults.
- **[libafl_libfuzzer_runtime](./libafl_libfuzzer_runtime)**: Runtime library for LibAFL's libFuzzer compatibility layer.

## Utility & Infrastrucutre

- **[build_id2](./build_id2)**: Updated and maintained build id library.
- **[core_affinity2](./core_affinity2)**: Core Affinity crate to bind to cores, cross platform.
- **[exceptional](./exceptional)**: Everything for your exception and signal handling needs.
- **[fast_rands](./fast_rands)**: Non-cryptographically, but quite fast, RNG implementations.
- **[libafl_asan](./libafl_asan)**: Address sanitizer library for LibAFL.
- **[libafl_core](./libafl_core)**: A platform-independent shared memory library for Rust.
- **[libafl_derive](./libafl_derive)**: Derive proc-macro crate for LibAFL.
- **[ll_mp](./ll_mp)**: A library for low level message passing.
- **[minibsod](./minibsod)**: A library to dump current register states, etc., on crash.
- **[no_std_time](./no_std_time)**: Time measurments that work in no_std environments.
- **[ownedref](./ownedref)**: Library to pass around references that will be owned types on deserialization.
- **[serde_anymap](./serde_anymap)**: A map that can retrieve values by type - and is SerDe serializable.
- **[shmem_providers](./shmem_providers)**: Platform independent shared memory providers for Windows, Linux, Android, iOS, ...
- **[tuple_list_ex](./tuple_list_ex)**: Useful Haskel-like extensions for the tuple_list crate.
