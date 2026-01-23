# Bootloader Fuzzing in QEMU/KVM with Intel Pt Tracing

A minimalistic example about how to create a LibAFL based fuzzer with Intel
PT tracing using QEMU/KVM to target a bootloader. The target is a nasty x86
bootloader that if detects a specific BIOS version, it hangs forever. The
fuzzer runs until it finds the right input for which the bootloader tries to
hang and then it exits.

During execution the fuzzer prints some statistics to the terminal, like the
number of executions and corpus size (the number of inputs the fuzzer marked
as interesting so far). At the end of the execution, the input causing the
crash is saved to the `crashes/` folder and printed to the terminal.

## How to build from source

You can build from source running `just` to build and then run the fuzzer
(requires `just`, `qemu` and `nasm` installed):

This command requires to run `sudo` to give the fuzzer the necessary
capabilities to use hardware tracing, you may have to enter `root` password.
