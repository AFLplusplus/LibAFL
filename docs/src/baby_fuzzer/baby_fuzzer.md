# A Simple LibAFL Fuzzer

This chapter discusses a naive fuzzer using the LibAFL API.
You will learn about basic entities such as `State`, `Observer`, and `Executor`.
While the following chapters discuss the components of LibAFL in detail, here we introduce the fundamentals.

We are going to fuzz a simple Rust function that panics under a condition. The fuzzer will be single-threaded and will stop after the crash, just like libFuzzer normally does.

You can find a complete version of this tutorial as an example fuzzer in [`fuzzers/baby_fuzzer`](https://github.com/AFLplusplus/LibAFL/tree/main/fuzzers/baby_fuzzer).

> ### Warning
>
> This example fuzzer is too naive for any real-world usage.
> Its purpose is solely to show the main components of the library, for a more in-depth walkthrough on building a custom fuzzer go to the [Tutorial chapter](../tutorial/intro.md) directly.

## Creating a project

We use cargo to create a new Rust project with LibAFL as a dependency. 

```sh
$ cargo new baby_fuzzer
$ cd baby_fuzzer
```

The generated `Cargo.toml` looks like the following:

```toml
[package]
name = "baby_fuzzer"
version = "0.1.0"
authors = ["Your Name <you@example.com>"]
edition = "2018"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
```

In order to use LibAFl we must add it as dependency adding `libafl = { path = "path/to/libafl/" }` under `[dependencies]`.
You can use the LibAFL version from crates.io if you want, in this case, you have to use `libafl = "*"` to get the latest version (or set it to the current version).

As we are going to fuzz Rust code, we want that a panic does not simply cause the program to exit, but raise an `abort` that can then be caught by the fuzzer.
To do that, we specify `panic = "abort"` in the [profiles](https://doc.rust-lang.org/cargo/reference/profiles.html).

Alongside this setting, we add some optimization flags for the compile when building in release mode.

The final `Cargo.toml` should look similar to the following:


```toml
[package]
name = "baby_fuzzer"
version = "0.1.0"
authors = ["Your Name <you@example.com>"]
edition = "2018"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
libafl = { path = "path/to/libafl/" }

[profile.dev]
panic = "abort"

[profile.release]
panic = "abort"
lto = true
codegen-units = 1
opt-level = 3
debug = true
```

## The function under test

Opening `src/main.rs`, we have an empty `main` function.
To start, we create the closure that we want to fuzz. It takes a buffer as input and panics if it starts with `"abc"`.

```rust
extern crate libafl;
use libafl::{
    bolts::AsSlice,
    inputs::{BytesInput, HasTargetBytes},
};

let mut harness = |input: &BytesInput| {
    let target = input.target_bytes();
    let buf = target.as_slice();
    if buf.len() > 0 && buf[0] == 'a' as u8 {
        if buf.len() > 1 && buf[1] == 'b' as u8 {
            if buf.len() > 2 && buf[2] == 'c' as u8 {
                panic!("=)");
            }
        }
    }
};
// To test the panic:
// let input = BytesInput::new("abc".as_bytes());
// harness(&input);
```

## Generating and running some tests

One of the main components that a LibAFL-based fuzzer uses is the State, a container of the data that is evolved during the fuzzing process.
Includes all State, such as the Corpus of inputs, the current rng state, and potential Metadata for the testcases and run.
In our `main` we create a basic State instance like the following:

```rust,ignore
// create a State from scratch
let mut state = StdState::new(
    // RNG
    StdRand::with_seed(current_nanos()),
    // Corpus that will be evolved, we keep it in memory for performance
    InMemoryCorpus::new(),
    // Corpus in which we store solutions (crashes in this example),
    // on disk so the user can get them after stopping the fuzzer
    OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
    &mut (),
    &mut ()
).unwrap();
```

It takes a random number generator, that is part of the fuzzer state, in this case, we use the default one `StdRand` but you can choose a different one. We seed it with the current nanoseconds.

As the second parameter, it takes an instance of something implementing the Corpus trait, InMemoryCorpus in this case. The corpus is the container of the testcases evolved by the fuzzer, in this case, we keep it all in memory.

We will discuss the last parameter later. The third parameter is another corpus, in this case, to store the testcases that are considered as "solutions" for the fuzzer. For our purpose, the solution is the input that triggers the panic. In this case, we want to store it to disk under the `crashes` directory, so we can inspect it.

Another required component is the EventManager. It handles some events such as the addition of a testcase to the corpus during the fuzzing process. For our purpose, we use the simplest one that just displays the information about these events to the user using a `Monitor` instance.

```rust,ignore
// The Monitor trait defines how the fuzzer stats are displayed to the user
let mon = SimpleMonitor::new(|s| println!("{}", s));

// The event manager handle the various events generated during the fuzzing loop
// such as the notification of the addition of a new item to the corpus
let mut mgr = SimpleEventManager::new(mon);
```

In addition, we have the Fuzzer, an entity that contains some actions that alter the State. One of these actions is the scheduling of the testcases to the fuzzer using a Scheduler.
We create it as QueueScheduler, a scheduler that serves testcases to the fuzzer in a FIFO fashion.

```rust,ignore
// A queue policy to get testcasess from the corpus
let scheduler = QueueScheduler::new();

// A fuzzer with feedbacks and a corpus scheduler
let mut fuzzer = StdFuzzer::new(scheduler, (), ());
```

Last but not least, we need an Executor that is the entity responsible to run our program under test. In this example, we want to run the harness function in-process (without forking off a child, for example), and so we use the `InProcessExecutor`.

```rust,ignore
// Create the executor for an in-process function
let mut executor = InProcessExecutor::new(
    &mut harness,
    (),
    &mut fuzzer,
    &mut state,
    &mut mgr,
)
.expect("Failed to create the Executor");
```

It takes a reference to the harness, the state, and the event manager. We will discuss the second parameter later.
As the executor expects that the harness returns an ExitKind object, we add `ExitKind::Ok` to our harness function.

Now we have the 4 major entities ready for running our tests, but we still cannot generate testcases.

For this purpose, we use a Generator, `RandPrintablesGenerator` that generates a string of printable bytes.

```rust,ignore
use libafl::generators::RandPrintablesGenerator;

// Generator of printable bytearrays of max size 32
let mut generator = RandPrintablesGenerator::new(32);

// Generate 8 initial inputs
state
    .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
    .expect("Failed to generate the initial corpus".into());
```

Now you can prepend the necessary `use` directives to your main.rs and compile the fuzzer.

```rust
extern crate libafl;

use std::path::PathBuf;
use libafl::{
    bolts::{current_nanos, rands::StdRand},
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    fuzzer::StdFuzzer,
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    schedulers::QueueScheduler,
    state::StdState,
};
```

When running, you should see something similar to:

```sh
$ cargo run
    Finished dev [unoptimized + debuginfo] target(s) in 0.04s
     Running `target/debug/baby_fuzzer`
[LOG Debug]: Loaded 0 over 8 initial testcases
```

## Evolving the corpus with feedbacks

Now you simply ran 8 randomly generated testcases, but none of them has been stored in the corpus. If you are very lucky, maybe you triggered the panic by chance but you don't see any saved file in `crashes`.

Now we want to turn our simple fuzzer into a feedback-based one and increase the chance to generate the right input to trigger the panic. We are going to implement a simple feedback based on the 3 conditions that are needed to reach the panic.

To do that, we need a way to keep track of if a condition is satisfied. The component that feeds the fuzzer with information about properties of a fuzzing run, the satisfied conditions in our case, is the Observer. We use the `StdMapObserver`, the default observer that uses a map to keep track of covered elements. In our fuzzer, each condition is mapped to an entry of such map.

We represent such map as a `static mut` variable.
As we don't rely on any instrumentation engine, we have to manually track the satisfied conditions in a map modifying our tested function:

```rust
extern crate libafl;
use libafl::{
    bolts::AsSlice,
    inputs::{BytesInput, HasTargetBytes},
    executors::ExitKind,
};

// Coverage map with explicit assignments due to the lack of instrumentation
static mut SIGNALS: [u8; 16] = [0; 16];

fn signals_set(idx: usize) {
    unsafe { SIGNALS[idx] = 1 };
}

// The closure that we want to fuzz
let mut harness = |input: &BytesInput| {
    let target = input.target_bytes();
    let buf = target.as_slice();
    signals_set(0);
    if buf.len() > 0 && buf[0] == 'a' as u8 {
        signals_set(1);
        if buf.len() > 1 && buf[1] == 'b' as u8 {
            signals_set(2);
            if buf.len() > 2 && buf[2] == 'c' as u8 {
                panic!("=)");
            }
        }
    }
    ExitKind::Ok
};
```

The observer can be created directly from the `SIGNALS` map, in the following way:

```rust,ignore
// Create an observation channel using the signals map
let observer = StdMapObserver::new("signals", unsafe { &mut SIGNALS });
```

The observers are usually kept in the corresponding executor as they keep track of information that is valid for just one run. We have then to modify our InProcessExecutor creation to include the observer as follows:

```rust,ignore
// Create the executor for an in-process function with just one observer
let mut executor = InProcessExecutor::new(
    &mut harness,
    tuple_list!(observer),
    &mut fuzzer,
    &mut state,
    &mut mgr,
)
.expect("Failed to create the Executor".into());
```

Now that the fuzzer can observe which condition is satisfied, we need a way to rate an input as interesting (i.e. worth of addition to the corpus) based on this observation. Here comes the notion of Feedback. The Feedback is part of the State and provides a way to rate input and its corresponding execution as interesting looking for the information in the observers. Feedbacks can maintain a cumulative state of the information seen so far in a metadata in the State, in our case it maintains the set of conditions satisfied in the previous runs.

We use MaxMapFeedback, a feedback that implements a novelty search over the map of the MapObserver. Basically, if there is a value in the observer's map that is greater than the maximum value registered so far for the same entry, it rates the input as interesting and updates its state.

Feedbacks are used also to decide if an input is a "solution". The feedback that does that is called the Objective Feedback and when it rates an input as interesting it is not saved to the corpus but to the solutions, written in the `crashes` folder in our case. We use the CrashFeedback to tell the fuzzer that if an input causes the program to crash it is a solution for us.

We need to update our State creation including the feedback state and the Fuzzer including the feedback and the objective:

```rust,ignore
extern crate libafl;
use libafl::{
    bolts::{current_nanos, rands::StdRand, tuples::tuple_list},
    corpus::{InMemoryCorpus, OnDiskCorpus},
    feedbacks::{MaxMapFeedback, CrashFeedback},
    fuzzer::StdFuzzer,
    state::StdState,
    observers::StdMapObserver,
};

// Feedback to rate the interestingness of an input
let mut feedback = MaxMapFeedback::new(&feedback_state, &observer);

// A feedback to choose if an input is a solution or not
let mut objective = CrashFeedback::new();

// create a State from scratch
let mut state = StdState::new(
    // RNG
    StdRand::with_seed(current_nanos()),
    // Corpus that will be evolved, we keep it in memory for performance
    InMemoryCorpus::new(),
    // Corpus in which we store solutions (crashes in this example),
    // on disk so the user can get them after stopping the fuzzer
    OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
    &mut feedback,
    &mut objective
).unwrap();

// ...

// A fuzzer with feedbacks and a corpus scheduler
let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
```

## The actual fuzzing

Now, after including the correct `use`, we can run the program, but the outcome is not so different from the previous one as the random generator does not take into account what we save as interesting in the corpus. To do that, we need to plug a Mutator.

Another central component of LibAFL are the Stages, that are actions done on individual inputs taken from the corpus. The MutationalStage mutates the input and executes it several times for instance.

As the last step, we create a MutationalStage that uses a mutator inspired by the havoc mutator of AFL.

```rust,ignore
use libafl::{
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    stages::mutational::StdMutationalStage,
    fuzzer::Fuzzer,
};

// ...

// Setup a mutational stage with a basic bytes mutator
let mutator = StdScheduledMutator::new(havoc_mutations());
let mut stages = tuple_list!(StdMutationalStage::new(mutator));

fuzzer
    .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
    .expect("Error in the fuzzing loop");
```

`fuzz_loop` will request a testcase for each iteration to the fuzzer using the scheduler and then it will invoke the stage.

After adding this code, we have a proper fuzzer, that can run a find the input that panics the function in less than a second.

```text
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
