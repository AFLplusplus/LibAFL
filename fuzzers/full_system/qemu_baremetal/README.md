# Qemu baremetal with launcher

This folder contains an example fuzzer for the qemu systemmode, using LLMP for fast multi-process fuzzing and crash detection.
The target is a simpel baremetal arm target.

It comes in three flavours (can be set through features):

-`low_level`: The low-level way to interact with QEMU.
-`breakpoint`: Interaction with QEMU using the command system, leveraging breakpoints.
-`sync_exit`: Interaction with QEMU using the command system, leveraging sync exits.

## Prerequisite

You will need to have `qemu-img` and `arm-none-eabi-gcc` installed.

On Ubuntu and Debian, you will need to run
```bash
sudo apt update
sudo apt -y install qemu-utils gcc-arm-none-eabi
```

## Build

Build one of the flavors (breakpoint by default):

```bash
just build
```

## Run

Run one of the flavors (breakpoint by default):

```bash
just run
```

This will build the desired fuzzer (src/fuzzer_<feature>.rs) and a small example binary based on FreeRTOS, which can run under a qemu emulation target.
Since the instrumentation is based on snapshots, QEMU needs a virtual drive (even if it is unused...).
Thus, the makefile creates a dummy QCOW2 image `dummy.qcow2` (can be found in the `target directory`).
Currently, the ``KERNEL`` variable is needed because the fuzzer does not parse QEMUs arguments to find the binary.
It is automatically set in the build script.