# Qemu systemmode with launcher

This folder contains an example fuzzer for the qemu systemmode, using LLMP for fast multi-process fuzzing and crash detection.

It comes in three flavours (can be set through features):

-`classic`: The low-level way to interact with QEMU.
-`breakpoint`: Interaction with QEMU using the command system, leveraging breakpoints.
-`sync_exit`: Interaction with QEMU using the command system, leveraging sync exits.

## Run

```bash
cargo make run
```

It is also possible to run the fuzzer with the other features:

```bash
cargo make <feature>
```

With feature being `classic`, `breakpoint` or `sync_exit`.

This will build the desired fuzzer (src/fuzzer_<feature>.rs) and a small example binary based on FreeRTOS, which can run under a qemu emulation target.
Since the instrumentation is based on snapshots, QEMU needs a virtual drive (even if it is unused...).
Thus, the makefile creates a dummy QCOW2 image `dummy.qcow2` (can be found in the `target directory`).
Currently the ``KERNEL`` variable is needed because the fuzzer does not parse QEMUs arguments to find the binary.
It is automatically set in the build script.