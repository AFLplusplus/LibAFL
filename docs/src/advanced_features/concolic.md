# Concolic Tracing and Hybrid Fuzzing

LibAFL has support for concolic tracing based on the [SymCC](https://github.com/eurecom-s3/symcc) instrumenting compiler.

For those uninitiated, the following text attempts to describe concolic tracing from the ground up using an example.
Then, we'll go through the relationship of SymCC and LibAFL concolic tracing.
Finally, we'll walk through building a basic hybrid fuzzer using LibAFL.

## Concolic Tracing by Example

Suppose you want to fuzz the following program:

```rust
fn target(input: &[u8]) -> i32 {
    match &input {
        // fictitious crashing input
        &[1, 3, 3, 7] => 1337,
        // standard error handling code
        &[] => -1,
        // representative of normal execution
        _ => 0 
    }
}
```

A simple coverage-maximizing fuzzer that generates new inputs somewhat randomly will have a hard time finding an input that triggers the fictitious crashing input.
Many techniques have been proposed to make fuzzing less random and more directly attempt to mutate the input to flip specific branches, such as the ones involved in crashing the above program.

Concolic tracing allows us to construct an input that exercises a new path in the program (such as the crashing one in the example) **analytically** instead of **stochastically** (ie. guessing).
In principle, concolic tracing works by observing all executed instructions in an execution of the program that depend on the input.
To understand what this entails, we'll run an example with the above program.

First, we'll simplify the program to simple if-then-else-statements:

```rust
fn target(input: &[u8]) -> i32 {
    if input.len() == 4 {
        if input[0] == 1 {
            if input[1] == 3 {
                if input[2] == 3 {
                    if input[3] == 7 {
                        return 1337;
                    } else {
                        return 0;
                    }
                } else {
                    return 0;
                }
            } else {
                return 0;
            }
        } else {
            return 0;
        }
    } else {
        if input.len() == 0 {
            return -1;
        } else {
            return 0;
        }
    }
}
```

Next, we'll trace the program on the input `[]`.
The trace would look like this:

```rust,ignore
Branch { // if input.len() == 4
    condition: Equals { 
        left: Variable { name: "input_len" }, 
        right: Integer { value: 4 } 
    }, 
    taken: false // This condition turned out to be false...
}
Branch { // if input.len() == 0
    condition: Equals { 
        left: Variable { name: "input_len" }, 
        right: Integer { value: 0 } 
    }, 
    taken: true // This condition turned out to be true!
}
```

Using this trace, we can easily deduce that we can force the program to take a different path by having an input of length 4 or having an input with non-zero length.
We do this by negating each branch condition and analytically solving the resulting 'expression'.
In fact, we can create these expressions for any computation and give them to an [SMT](https://en.wikipedia.org/wiki/Satisfiability_modulo_theories)-Solver that will generate an input that satisfies the expression (as long as such an input exists).

In hybrid fuzzing, we combine this tracing + solving approach with more traditional fuzzing techniques.

## Concolic Tracing in LibAFL, SymCC and SymQEMU

The concolic tracing support in LibAFL is implemented using SymCC.
SymCC is a compiler plugin for clang that can be used as a drop-in replacement for a normal C or C++ compiler.
SymCC will instrument the compiled code with callbacks into a runtime that can be supplied by the user.
These callbacks allow the runtime to construct a trace that is similar to the previous example.

### SymCC and its Runtimes

SymCC ships with 2 runtimes:

* A 'simple' runtime that attempts to negate and analytically solve any branch conditions it comes across using [Z3](https://github.com/Z3Prover/z3/wiki) and
* A [QSym](https://github.com/sslab-gatech/qsym)-based runtime, which does a bit more filtering on the expressions and also solves them using Z3.

The integration with LibAFL, however, requires you to **BYORT** (_bring your own runtime_) using the [`symcc_runtime`](https://docs.rs/symcc_runtime/0.1/symcc_runtime) crate.
This crate allows you to easily build a custom runtime out of the built-in building blocks or create entirely new runtimes with full flexibility.
Check out the `symcc_runtime` docs for more information on how to build your own runtime.

### SymQEMU

[SymQEMU](https://github.com/eurecom-s3/symqemu) is a sibling project to SymCC.
Instead of instrumenting the target at compile-time, it inserts instrumentation via dynamic binary translation, building on top of the [`QEMU`](https://www.qemu.org) emulation stack.
This means that using SymQEMU, any (x86) binary can be traced without the need to build in instrumentation ahead of time.
The `symcc_runtime` crate supports this use case and runtimes built with `symcc_runtime` also work with SymQEMU.

## Hybrid Fuzzing in LibAFL

The LibAFL repository contains an [example hybrid fuzzer](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/structure_aware/libfuzzer_stb_image_concolic).

There are three main steps involved with building a hybrid fuzzer using LibAFL:

1. Building a runtime,
2. choosing an instrumentation method and
3. building the fuzzer.

Note that the order of these steps is important.
For example, we need to have a runtime ready before we can do instrumentation with SymCC.

### Building a Runtime

Building a custom runtime can be done easily using the `symcc_runtime` crate.
Note, that a custom runtime is a separate shared object file, which means that we need a separate crate for our runtime.
Check out the [example hybrid fuzzer's runtime](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/structure_aware/libfuzzer_stb_image_concolic/runtime) and the [`symcc_runtime` docs](https://docs.rs/symcc_runtime/0.1/symcc_runtime) for inspiration.

### Instrumentation

There are two main instrumentation methods to make use of concolic tracing in LibAFL:

* Using a **compile-time** instrumented target with **SymCC**.
This only works when the source is available for the target and the target is reasonably easy to build using the SymCC compiler wrapper.
* Using **SymQEMU** to dynamically instrument the target at **runtime**.
This avoids building a separate instrumented target with concolic tracing instrumentation and so does not require source code.

It should be noted, however, that the 'quality' of the generated expressions can be significantly worse and SymQEMU generally produces significantly more and significantly more convoluted expressions than SymCC.
Therefore, it is recommended to use SymCC over SymQEMU when possible.

#### Using SymCC

The target needs to be instrumented ahead of fuzzing using SymCC.
How exactly this is done does not matter.
However, the SymCC compiler needs to be made aware of the location of the runtime that it should instrument against.
This is done by setting the `SYMCC_RUNTIME_DIR` environment variable to the directory which contains the runtime (typically the `target/(debug|release)` folder of your runtime crate).

The example hybrid fuzzer instruments the target in its [`build.rs` build script](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/structure_aware/libfuzzer_stb_image_concolic/fuzzer/build.rs#L50).
It does this by cloning and building a copy of SymCC and then using this version to instrument the target.
The [`symcc_libafl` crate](https://docs.rs/symcc_libafl) contains helper functions for cloning and building SymCC.

Make sure you satisfy the [build requirements](https://github.com/eurecom-s3/symcc#readme) of SymCC before attempting to build it.

#### Using SymQEMU

Build SymQEMU according to its [build instructions](https://github.com/eurecom-s3/symqemu#readme).
By default, SymQEMU looks for the runtime in a sibling directory.
Since we don't have a runtime there, we need to explicitly set the `--symcc-build` argument of the `configure` script to the path of your runtime.

### Building the Fuzzer

No matter the instrumentation method, the interface between the fuzzer and the instrumented target should now be consistent.
The only difference between using SymCC and SymQEMU should be the binary that represents the target:
In the case of SymCC it will be the binary that was build with instrumentation and with SymQEMU it will be the emulator binary (eg. `x86_64-linux-user/symqemu-x86_64`), followed by your uninstrumented target binary and its arguments.

You can use the [`CommandExecutor`](https://docs.rs/libafl/latest/libafl/executors/command/struct.CommandExecutor.html) to execute your target ([example](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/structure_aware/libfuzzer_stb_image_concolic/fuzzer/src/main.rs#L244)).
When configuring the command, make sure you pass the `SYMCC_INPUT_FILE` environment variable (set to the input file path), if your target reads input from a file (instead of standard input).

#### Serialization and Solving

While it is perfectly possible to build a custom runtime that also performs the solving step of hybrid fuzzing in the context of the target process, the intended use of the LibAFL concolic tracing support is to serialize the (filtered and pre-processed) branch conditions using the [`TracingRuntime`](https://docs.rs/symcc_runtime/0.1/symcc_runtime/tracing/struct.TracingRuntime.html).
This serialized representation can be deserialized in the fuzzer process for solving using a [`ConcolicObserver`](https://docs.rs/libafl/latest/libafl/observers/concolic/struct.ConcolicObserver.html) wrapped in a [`ConcolicTracingStage`](https://docs.rs/libafl/latest/libafl/stages/concolic/struct.ConcolicTracingStage.html), which will attach a [`ConcolicMetadata`](https://docs.rs/libafl/latest/libafl/observers/concolic/struct.ConcolicMetadata.html) to every [`TestCase`](https://docs.rs/libafl/latest/libafl/corpus/testcase/struct.Testcase.html).

The `ConcolicMetadata` can be used to replay the concolic trace and to solve the conditions using an SMT-Solver.
Most use-cases involving concolic tracing, however, will need to define some policy around which branches they want to solve.
The [`SimpleConcolicMutationalStage`](https://docs.rs/libafl/latest/libafl/stages/concolic/struct.SimpleConcolicMutationalStage.html) can be used for testing purposes.
It will attempt to solve all branches, like the original simple backend from SymCC, using Z3.

### Example

The example fuzzer shows how to use the [`ConcolicTracingStage` together with the `SimpleConcolicMutationalStage`](https://github.com/AFLplusplus/LibAFL/blob/main/fuzzers/structure_aware/libfuzzer_stb_image_concolic/fuzzer/src/main.rs#L222) to build a basic hybrid fuzzer.
