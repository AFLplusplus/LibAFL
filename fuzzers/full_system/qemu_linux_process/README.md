# LibAFL QEMU Systemmode for Linux process fuzzing

This folder contains an example linux process fuzzer using qemu systemmode.
This is demo, most of the time for classic linux process fuzzing, it is better to use a more conventional method.

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