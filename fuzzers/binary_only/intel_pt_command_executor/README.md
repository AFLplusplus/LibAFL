# Linux Binary-Only Fuzzer with Intel PT Tracing

This fuzzer is designed to target a Linux binary (without requiring source code instrumentation) and leverages Intel
Processor Trace (PT) to compute code coverage.

## Prerequisites

- A Linux host with an Intel Processor Trace (PT) compatible CPU
- `just` installed
- Sudo access to grant necessary capabilities to the fuzzer

## How to Run the Fuzzer

To compile and run the fuzzer (and the target program) execute the following command:
```sh
just
```

> **Note**: This command may prompt you for your password to assign capabilities required for Intel PT. If you'd prefer
> not to run it with elevated permissions, you can review and execute the commands from `Makefile.toml`
> individually.
