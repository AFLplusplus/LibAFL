# verilator_cva6

This fuzzer demonstrates the use of `libafl_verilator` to perform fuzzing against a full processor (namely, [CVA6]).

## Prerequisites

You must have a valid RISC-V installation with both [riscv-gnu-toolchain] (as we build a RISC-V executable) and
[riscv-isa-sim] (for fesvr dependency) and a Verilator installation. These should be referred to by the `RISCV` and
`VERILATOR_ROOT` environmental variables, respectively, before attempting to build this fuzzer.

## Notable Takeaways

If you wish to build a verilated hardware fuzzer yourself, here are a few things to pay particular focus to.

### Host OS Interactions

Our particular target uses interactions with the host OS to load the base executable via the debug transport module.
This operation represents a majority of the runtime, which is why I decided to develop this fuzzer with forking at its
heart. If you are working with similar designs (e.g., other processors or SoCs), you should consider doing the same.
See `src/main.rs` for how this is implemented. Please do reach out to me ([Addison]) if you need help with this, as I
encountered quite a bit of trouble with making CVA6 fuzzer-compatible.

### Verilator

#### Threading

Verilator has a fickle heart. To ensure that we are able to fork in a valid manner, we need to make sure that our design
is verilated without threads or locks, as these can cause the forked target to await a lock on a thread that isn't
associated with the child process.

In `build.rs`, we generate the model with the Verilator flags `--no-threads` and `--no-timing` and we build the
verilated_* includes with `VL_NO_LEGACY` to prevent us from accidentally using forceably-threaded legacy components.

#### Harness

Your harness must offer the symbol `VerilatedContext *__libafl_verilator_context` which is updated to the model's
context pointer. This is used by `libafl_verilator` to extract coverage from the design without the use of threading.

In addition, you should expose ticking, initialisation, and finalisation functionality to your fuzzer. This is not
explicitly required by `libafl_verilator` as the specific requirements will differ between targeted designs. Refer to
`build.rs`, `harness.h`, and `ariane_tb_libafl.cpp` for details on how this was accomplished.

[CVA6]: https://github.com/openhwgroup/cva6
[riscv-gnu-toolchain]: https://github.com/riscv-collab/riscv-gnu-toolchain
[riscv-isa-sim]: https://github.com/riscv-software-src/riscv-isa-sim/
[Addison]: mailto:research@addisoncrump.info