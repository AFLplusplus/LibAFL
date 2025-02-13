# LibAFL QEMU Systemmode for Linux kernel fuzzing

This folder contains an example linux kernel fuzzer using qemu systemmode.

## Warning

For now, only the fuzzer is public. We plan to release the auto-builder for linux
images in the near future.
If you wish to experiment now, you will need to build the linux image manually.

## Prerequisite

TODO

## Build

To build the target:
```bash
cargo make target
```

To build the fuzzer:
```bash
cargo make build
```

It is also possible to update the target if it only changes "runtime" files.
This is equivalent to rebuilding the target, it is only faster since it does not need to rebuild the image from scratch.
Check [The linux builder repository](https://github.com/AFLplusplus/linux-qemu-image-builder.git) for more details on the specifics.
```bash
cargo make target_update
```

## Run

To run the fuzzer:
```bash
cargo make run
```