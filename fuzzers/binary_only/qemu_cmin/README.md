# qemu_cmin

This folder contains an example fuzzer which runs each entry in the input corpus and minimizes the input corpus. This fuzzer also distributes the test cases in
the input corupus evenly across the selected cores.

The following architectures are supported:
* arm
* aarch64
* i386
* x86_64
* mips
* ppc

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
just run
```

```bash
just <arch>
```
