# Migrating from LibAFL <0.11 to 0.11

We moved the old `libafl::bolts` module to its own crate called `libafl_bolts`.
For this, imports for types in LibAFL bolts have changed in version 0.11, everything else should remain the same.

## Reasons for This Change

With the change we can now use a lot of low-level features of LibAFL for projects that are unrelated to fuzzing, or just completely different to LibAFL.
Some cross-platform things in bolts include

* SerdeAnyMap: a map that stores and retrieves elements by type and is serializable and deserializable
* ShMem: A cross-platform (Windows, Linux, Android, MacOS) shared memory implementation
* LLMP: A fast, lock-free IPC mechanism via SharedMap
* Core_affinity: A maintained version of `core_affinity` that can be used to get core information and bind processes to cores
* Rands: Fast random number generators for fuzzing (like [RomuRand](https://www.romu-random.org/))
* MiniBSOD: get and print information about the current process state including important registers.
* Tuples: Haskel-like compile-time tuple lists
* Os: OS specific stuff like signal handling, windows exception handling, pipes, and helpers for `fork`

## What changed

You will need to move all `libafl::bolts::` imports to `libafl_bolts:::` and add the crate dependency in your Cargo.toml (and specify feature flags there).
As only exception, the `libafl::bolts::launcher::Launcher` has moved to `libafl::events::launcher::Launcher` since it has fuzzer and `EventManager` specific code.
If you are using `prelude`, you may need to also ad `libafl_bolts::prelude`.

That's it.
Enjoy using `libafl_bolts` in other projects.
