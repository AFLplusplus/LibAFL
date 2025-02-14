# qemu_launcher_

This folder contains an example fuzzer that will fuzz binary-only targets, cross-architecture, on Linux.
It's using LLMP for fast multi-process fuzzing and crash detection.
This automatically spawns `n` child processes, and binds them to a free core.

To adapt the fuzzer to your custom target, change [`harness.rs`](./src/harness.rs).

The following architectures are supported:

* arm
* aarch64
* i386
* x86_64
* mips
* ppc

For usermode, this fuzzer supports injection fuzzing with `-j`.

## Prerequisites

```bash
sudo apt install \
    gcc-arm-linux-gnueabi \
    g++-arm-linux-gnueabi \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    gcc \
    g++ \
    gcc-mipsel-linux-gnu \
    g++-mipsel-linux-gnu \
    gcc-powerpc-linux-gnu \
    g++-powerpc-linux-gnu \
    libsqlite3-dev
```

## Run

Defaults to `x86_64` architecture. Change the architecture by 

```bash
just run
```

```bash
just <arch>
```
