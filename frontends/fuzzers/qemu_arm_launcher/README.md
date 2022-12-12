# LibAFL with launcher for libpng with qemu arm32 in usermode

This folder contains an example fuzzer for libpng using the qemu emulator in arm32 usermode.
To show off crash detection, we added an optional undefined instruction to the harness.
Everything has been tested on Linux.

In contrast to the normal libfuzzer libpng example, this uses the `launcher` feature, that automatically spawns `n` child processes, and binds them to a free core.

## Prerequisites
```bash
sudo apt install gcc-arm-linux-gnueabi g++-arm-linux-gnueabi
```

## Run

```bash
cargo make run
```

## Run with artifical crash

```bash
cargo make run_crashing
```
