# QEMU AddressSanitizer Runtime

This library is the injected runtime used by QEMU AddressSanitizer (QASan).

The original repository is [here](https://github.com/andreafioraldi/qasan).

The version embedded in libafl_qemu is an updated version of just the usermode part
and this runtime is injected via LD_PRELOAD (so works just for dynamically
linked binaries).

For debugging purposes, we still suggest to run the original QASan as the
stacktrace support for ARM (just a debug feature, it does not affect the bug
finding capabilities during fuzzing) is WIP.
