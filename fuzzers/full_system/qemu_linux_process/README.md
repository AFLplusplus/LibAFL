# LibAFL QEMU Systemmode for Linux process fuzzing

This folder contains an example linux process fuzzer using qemu systemmode.
This is demo, most of the time for classic linux process fuzzing, it is better to use a more conventional method.

## Warning

For now, only the fuzzer is public. We plan to release the auto-builder for linux
images in the near future.
If you wish to experiment now, you will need to build the linux image manually.

## Prerequisite

TODO

## Build

To build the target:
```bash
just target
```

To build the fuzzer:
```bash
just build
```

It is also possible to update the target if it only changes "runtime" files.
This is equivalent to rebuilding the target, it is only faster since it does not need to rebuild the image from scratch.
Check [The linux builder repository](https://github.com/AFLplusplus/linux-qemu-image-builder.git) for more details on the specifics.
```bash
just target_update
```

## Run

To run the fuzzer:
```bash
just run
```