`libafl_nyx` is the `libafl`'s front-end for the [nyx fuzzing framework](https://github.com/nyx-fuzz), which facilitates fuzzing in virtual machines such as qemu. This crate provides both the standalone mode and parallel mode:

- In standalone mode, no VM snapshot is serialized and stored in the working directory. That might be useful if you really want to run the fuzzer with only one process (meaning one VM).
- In parallel mode, the first fuzzer process (parent) has to create the VM snapshot while all other child processes will wait for the snapshot files to appear in the working directory.

In order to use this crate, you need to specify the shared directory and mode in `NyxHelper`, then use `NyxExecutor`. For more details, please see `./fuzzers/nyx_libxml2_standalone` and `./fuzzers/nyx_libxml2_parallel`.