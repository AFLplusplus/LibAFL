# qemu_launcher_

This folder contains an example fuzzer for libpng, using LLMP for fast multi-process fuzzing and crash detection. It has been tested on Linux.
This automatically spawns n child processes, and binds them to a free core.

The following architectures are supported:
* arm
* aarch64
* i386
* x86_64
* mips
* ppc

Note that the injection feature `-j` is currently only supported on x86_64
and aarch64.

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
    g++-powerpc-linux-gnu
```

## Run

Defaults to `x86_64` architecture
```bash
cargo make run
```

```bash
cargo make <arch>
```
