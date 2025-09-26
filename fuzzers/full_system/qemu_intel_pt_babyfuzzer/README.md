# Baby fuzzer using qemu systemmode with KVM and Intel PT

This is a minimalistic example about how to create a libafl_qemu based fuzzer with Intel PT tracing.

It runs on a single core until a crash occurs and then exits.

The tested program is a dummy bootloader without any instrumentation.

After building this example with `cargo build`, you need to give to the executable the necessary capabilities with
`sudo setcap cap_ipc_lock,cap_sys_ptrace,cap_sys_admin,cap_syslog=ep ./target/debug/intel_pt_baby_fuzzer`.

This fuzzer is compatible with Linux hosts only having an Intel PT (and KVM) compatible CPU.

## how to run

```sh
just
```

## Prerequisites

- Linux
- KVM and Intel Processor Trace (PT) compatible CPU
- just
- Sudo to grant necessary capabilities to the fuzzer (needed to use Intel PT)
- QEMU installed (needed for the bios and for the `qemu-img` utility)
