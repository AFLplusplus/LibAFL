# Qemu systemmode with launcher

This folder contains an example fuzzer for the qemu systemmode, using LLMP for fast multi-process fuzzing and crash detection.

## Build

To build this example, run

```bash
cargo build --release
cd example; sh build.sh; cd ..
```

This will build the the fuzzer (src/fuzzer.rs) and a small example binary based on FreeRTOS, which can run under a qemu emulation target.

## Run

Since the instrumentation is based on snapshtos QEMU needs a virtual drive (even if it is unused...).
Create on and then run the fuzzer:
```bash
# create an image
qemu-img create -f qcow2 dummy.qcow2 32M
# run the fuzzer
KERNEL=./example/example.elf target/release/qemu_systemmode -icount shift=auto,align=off,sleep=off -machine mps2-an385 -monitor null -kernel ./example/example.elf -serial null -nographic -snapshot -drive if=none,format=qcow2,file=dummy.qcow2 -S
```
Currently the ``KERNEL`` variable is needed because the fuzzer does not parse QEMUs arguments to find the binary.