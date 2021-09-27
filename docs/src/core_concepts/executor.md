# Executor

In different fuzzers, this concept of executing the program under test means each run is now always the same.
For instance, for in-memory fuzzers like libFuzzer an execution is a call to an harness function, for hypervisor-based fuzzers like [kAFL](https://github.com/IntelLabs/kAFL) instead an entire operating system is started from a snapshot for each run.

In our model, an Executor is the entity that defines not only how to execute the target, but all the volatile operations that are related to just a single run of the target.

So the Executor is for instance responsible to inform the program about the input that the fuzzer wants to use in the run, writing to a memory location for instance or passing it as a parameter to the harness function.

In our model, it can also hold a set of Observers connected with each execution.

In Rust, we bind this concept to the [`Executor`](https://docs.rs/libafl/0/libafl/executors/trait.Executor.html) trait. A structure implementing this trait must implement [`HasObservers`](https://docs.rs/libafl/0/libafl/executors/trait.HasObservers.html) too if wants to hold a set of Observers.

By default, we implement some commonly used Executors such as [`InProcessExecutor`](https://docs.rs/libafl/0/libafl/executors/inprocess/struct.InProcessExecutor.html) is which the target is a harness function providing in-process crash detection. Another Executor is the [`ForkserverExecutor`](https://docs.rs/libafl/0/libafl/executors/forkserver/struct.ForkserverExecutor.html) that implements an AFL-like mechanism to spawn child processes to fuzz.

A common pattern when creating an Executor is wrapping an existing one, for instance [`TimeoutExecutor`](https://docs.rs/libafl/0.6.1/libafl/executors/timeout/struct.TimeoutExecutor.html) wraps an executor and install a timeout callback before calling the original run function of the wrapped executor.
