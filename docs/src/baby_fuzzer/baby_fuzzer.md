# A Simple LibAFL Fuzzer

This chapter discusses a naive fuzzer using the LibAFL API.
You will learn about basic entities such as `State`, `Observer`, and `Executor`.
While the following chapters discuss the components of LibAFL in detail, here we introduce the fundamentals.

We are going to fuzz a simple Rust function that panics under a condition. The fuzzer will be single-threaded and will stop after the crash, just like libFuzzer normally does.

You can find a complete version of this tutorial as an example fuzzer in [`fuzzers/baby/baby_fuzzer`](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/baby/baby_fuzzer).

> ### Warning
>
> This example fuzzer is too naive for any real-world usage.
> Its purpose is solely to show the main components of the library, for a more in-depth walkthrough on building a custom fuzzer go to the [Tutorial chapter](../tutorial/intro.md) directly.

## Creating a project

We use cargo to create a new Rust project with LibAFL as a dependency.

```console
$ cargo new baby_fuzzer
$ cd baby_fuzzer
```

The generated `Cargo.toml` looks like the following:

```toml
{{#include ../../listings/baby_fuzzer/listing-01/Cargo.toml}}
```

In order to use LibAFl we must add it as dependency adding `libafl = { path = "path/to/libafl/" }` under `[dependencies]`.
That path actually needs to point to the `libafl` directory within the cloned repo, not the root of the repo itself.
You can use the LibAFL version from [crates.io](https://crates.io/crates/libafl) if you want, in this case, you have to use `libafl = "*"` to get the latest version (or set it to the current version).

As we are going to fuzz Rust code, we want that a panic does not simply cause the program to exit, but raise an `abort` that can then be caught by the fuzzer.
To do that, we specify `panic = "abort"` in the [profiles](https://doc.rust-lang.org/cargo/reference/profiles.html).

Alongside this setting, we add some optimization flags for the compilation, when building in release mode.

The final `Cargo.toml` should look similar to the following:

```toml
{{#include ../../listings/baby_fuzzer/listing-02/Cargo.toml}}
```


## The function under test

Opening `src/main.rs`, we have an empty `main` function.
To start, we create the closure that we want to fuzz. It takes a buffer as input and panics if it starts with `"abc"`.
`ExitKind` is used to inform the fuzzer about the harness' exit status.

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-03/src/main.rs}}
```

To test the crash manually, you can add a feature in `Cargo.toml` that enables the call that triggers the panic:

```toml
{{#include ../../listings/baby_fuzzer/listing-03/Cargo.toml:23:25}}
```

And then run the program with that feature activated:

```console
$ cargo run -F panic
```

And you should see the program crash as expected.

## Generating and running some tests

One of the main components that a LibAFL-based fuzzer uses is the State, a container of the data that will evolve during the fuzzing process.
It includes all state, such as the Corpus of inputs, the current RNG state, and potential Metadata for the testcases and run.
In our `main` we create a basic State instance like the following:


```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-04/src/main.rs:state}}
```

- The first parameter is a random number generator, that is part of the fuzzer state, in this case, we use the default one `StdRand`, but you can choose a different one. We seed it with the current nanoseconds.
- The second parameter is an instance of something implementing the Corpus trait, `InMemoryCorpus` in this case. The corpus is the container of the testcases evolved by the fuzzer, in this case, we keep it all in memory.

  To avoid type annotation error, you can use `InMemoryCorpus::<BytesInput>::new()` to replace `InMemoryCorpus::new()`. If not, type annotation will be automatically inferred when adding `executor`.

- The third parameter is another Corpus that stores the "solution" testcases for the fuzzer. For our purpose, the solution is the input that triggers the panic. In this case, we want to store it to disk under the `crashes` directory, so we can inspect it.
- The last two parameters are feedback and objective, we will discuss them later.

Another required component is the **EventManager**. It handles some events such as the addition of a testcase to the corpus during the fuzzing process. For our purpose, we use the simplest one that just displays the information about these events to the user using a `Monitor` instance.

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-04/src/main.rs:event_manager}}
```

In addition, we have the **Fuzzer**, an entity that contains some actions that alter the State. One of these actions is the scheduling of the testcases to the fuzzer using a **Scheduler**.
We create it as `QueueScheduler`, a scheduler that serves testcases to the fuzzer in a FIFO fashion.

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-04/src/main.rs:scheduler_fuzzer}}
```

Last but not least, we need an **Executor** that is the entity responsible to run our program under test. In this example, we want to run the harness function in-process (without forking off a child, for example), and so we use the `InProcessExecutor`.

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-04/src/main.rs:executor}}
```

It takes a reference to the harness, the state, and the event manager. We will discuss the second parameter later.
As the executor expects that the harness returns an ExitKind object, so we have added `ExitKind::Ok` to our harness function before.

Now we have the 4 major entities ready for running our tests, but we still cannot generate testcases.

For this purpose, we use a **Generator**, `RandPrintablesGenerator` that generates a string of printable bytes.

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-04/src/main.rs:generator}}
```

Now you can prepend the necessary `use` directives to your main.rs and compile the fuzzer.

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-04/src/main.rs:use}}
```

When running, you should see something similar to:

```console
$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.04s
     Running `target/debug/baby_fuzzer`
[LOG Debug]: Loaded 0 over 8 initial testcases
```

## Evolving the corpus with feedbacks

Now you simply ran 8 randomly generated testcases, but none of them has been stored in the corpus. If you are very lucky, maybe you triggered the panic by chance but you don't see any saved file in `crashes`.

Now we want to turn our simple fuzzer into a feedback-based one and increase the chance to generate the right input to trigger the panic. We are going to implement a simple feedback based on the 3 conditions that are needed to reach the panic. To do that, we need a way to keep track of if a condition is satisfied.

**Observer** can record the information about properties of a fuzzing run and then feeds the fuzzer. We use the `StdMapObserver`, the default observer that uses a map to keep track of covered elements. In our fuzzer, each condition is mapped to an entry of such map.

We represent such map as a `static mut` variable.
As we don't rely on any instrumentation engine, we have to manually track the satisfied conditions by `signals_set` in our harness:

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-05/src/main.rs:signals}}
```

The observer can be created directly from the `SIGNALS` map, in the following way:

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-05/src/main.rs:observer}}
```

The observers are usually kept in the corresponding executor as they keep track of information that is valid for just one run. We have then to modify our InProcessExecutor creation to include the observer as follows:

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-05/src/main.rs:executor_with_observer}}
```

Now that the fuzzer can observe which condition is satisfied, we need a way to rate an input as interesting (i.e. worth of addition to the corpus) based on this observation. Here comes the notion of Feedback.

**Feedback** is part of the State and provides a way to rate input and its corresponding execution as interesting looking for the information in the observers. Feedbacks can maintain a cumulative state of the information seen so far in a metadata in the State, in our case it maintains the set of conditions satisfied in the previous runs.

We use `MaxMapFeedback`, a feedback that implements a novelty search over the map of the MapObserver. Basically, if there is a value in the observer's map that is greater than the maximum value registered so far for the same entry, it rates the input as interesting and updates its state.

**Objective Feedback** is another kind of Feedback which decides if an input is a "solution". It will save input to solutions(`./crashes` in our case) rather than corpus when the input is rated interesting. We use `CrashFeedback` to tell the fuzzer that if an input causes the program to crash it is a solution for us.

We need to update our State creation including the feedback state and the Fuzzer including the feedback and the objective:

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-05/src/main.rs:state_with_feedback_and_objective}}
```

Once again, you need to add the necessary `use` directives for this to work properly:

```rust
{{#rustdoc_include ../../listings/baby_fuzzer/listing-05/src/main.rs:use}}
```

## The actual fuzzing

Now, we can run the program, but the outcome is not so different from the previous one as the random generator does not take into account what we save as interesting in the corpus. To do that, we need to plug a Mutator.

**Stages** perform actions on individual inputs, taken from the corpus.
For instance, the `MutationalStage` executes the harness several times in a row, every time with mutated inputs.

As the last step, we create a MutationalStage that uses a mutator inspired by the havoc mutator of AFL.

```rust,ignore
{{#rustdoc_include ../../listings/baby_fuzzer/listing-06/src/main.rs:mutational_stage}}
```

`fuzz_loop` will request a testcase for each iteration to the fuzzer using the scheduler and then it will invoke the stage.

Again, we need to add the new `use` directives:

```rust,ignore
{{#rustdoc_include ../../listings/baby_fuzzer/listing-06/src/main.rs:use}}
```

After adding this code, we have a proper fuzzer, that can run and find the input that panics the function in less than a second.

```console
$ cargo run
   Compiling baby_fuzzer v0.1.0 (/home/andrea/Desktop/baby_fuzzer)
    Finished dev [unoptimized + debuginfo] target(s) in 1.56s
     Running `target/debug/baby_fuzzer`
[New Testcase] clients: 1, corpus: 2, objectives: 0, executions: 1, exec/sec: 0
[LOG Debug]: Loaded 1 over 8 initial testcases
[New Testcase] clients: 1, corpus: 3, objectives: 0, executions: 804, exec/sec: 0
[New Testcase] clients: 1, corpus: 4, objectives: 0, executions: 1408, exec/sec: 0
thread 'main' panicked at '=)', src/main.rs:35:21
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
Crashed with SIGABRT
Child crashed!
[Objective] clients: 1, corpus: 4, objectives: 1, executions: 1408, exec/sec: 0
Waiting for broker...
Bye!
```

As you can see, after the panic message, the `objectives` count of the log increased by one and you will find the crashing input in `crashes/`.

The complete code can be found in [`./fuzzers/baby/baby_fuzzer`](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/baby/baby_fuzzer) alongside other `baby_` fuzzers.
