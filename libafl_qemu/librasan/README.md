# Asan
`asan` is a library intended to be used by a guest running in QEMU to
support address sanitizer.

It has a modular design intended to support different use cases and
environments. The following initial variants are proposed:

- `qasan` - Intended as a drop in replacement for the original libqasan,
this will have dependency on `libc` and will interact with QEMU using the
despoke syscall interface to perform memory tracking and shadowing.
- `gasan` - This is similar to `qasan`, but rather than having QEMU perform
the management of the shadow memory and memory tracking, this work will be
carried out purely in the guest (and hence should be more performant).
- `zasan` - This variant is intended to have no dependencies on libc, nor
any other libraries. It is intended to be used in bare-metal targets or
targets which have statically linked `libc`.

The componentized nature of the design is intended to permit the user to
adapt `asan` to their needs with minimal modification by selecting and
combining alternative implementations of the various key components.

## Features
- `dlmalloc` - Enable support for the dlmalloc allocator backend.
- `guest` - Enable support for shadow memory and tracking in the guest
- `host` - Enable support for shadow memory and tracking in the host
- `libc` - Enable use of `LibcMmap` to support creation of mappings using
`libc`
- `linux` - Enable use of `LinuxMmap` to support creation of mappings and
host interaction using `rustix`.
- `std` - Disable the magic used to support `no_std` environments

## Building
This project make use of `VSCode` devcontainers in order to provide a consistent
build environment. It should be noted that the cross compilers in `ubuntu`
conflict with each other and hence the compiler for `i686` has been installed
using ubuntu's 32-bit packages.

A comprehensive number of build tasks are included in `.vscode/tasks.json`,
but the following is a short list of common build commands:

```bash
$ cargo make -p x64_release # Build for x64 in release mode
$ cargo doc # Build documentation (recommended).
$ cargo make fuzz-guest-shadow-release # Fuzz the guest shadow implementation
$ cargo make fuzz-guest-tracking-release # Fuzz the guest tracking implementation
```

## Testing
This project makes use of a number of unit and integration tests to validate the
implementation.

## Fuzzing
The project also includes a couple of fuzzing harnesses supported by
`cargo-fuzz` in order to supplement unit and integration tests.

## TODO
* Further tests are needed for the allocator frontend implementation.
* Implementation for the various `libc` functions which we wish to override.
* Support for patching functions to redirect execution to an implementation
provided by the library (e.g. memmove, memcpy, strcpy etc).
* Rustix requires updates to provide proper support for `powerpc` targets.
