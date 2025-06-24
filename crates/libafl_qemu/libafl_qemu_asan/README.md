# libafl_qemu_asan

`libafl_qemu_asan` is a library intended to be used by a guest running in QEMU to
support address sanitizer.

It has a modular design intended to support different use cases and
environments. The following initial variants are implemented:

- `libafl_qemu_asan_host` - Intended as a drop in replacement for the original
libqasan, this will interact with QEMU using the bespoke syscall interface to
perform memory tracking and shadow mapping.
- `libafl_qemu_asan_guest` - This is similar to `libafl_qemu_asan_host`, but
rather than having QEMU perform the management of the shadow memory and memory
tracking, this work will be
carried out purely in the guest (and hence should be more performant).
- `libafl_qemu_asan_nolibc` - This variant is intended to have no dependencies
on libc, nor any other libraries. It is intended to be used as a starting point
for bare-metal targets or targets which have statically linked `libc`.

The componentized nature of the design is intended to permit the user to
adapt `libafl_qemu_asan` to their needs with minimal modification by selecting
and combining alternative implementations of the various key components.

## Features

- `dlmalloc` - Enable support for the dlmalloc allocator backend.
- `guest` - Enable support for shadow memory and tracking in the guest
- `host` - Enable support for shadow memory and tracking in the host
- `libc` - Enable use of `LibcMmap` to support creation of mappings using
`libc`
- `linux` - Enable use of `LinuxMmap` to support creation of mappings and
host interaction using `rustix`.
- `std` - Disable the magic used to support `no_std` environments

## Testing

This project makes use of a number of unit and integration tests to validate the
implementation.

## Fuzzing

The project also includes a couple of fuzzing harnesses supported by
`cargo-fuzz` in order to supplement unit and integration tests.
