# Executor

In different fuzzers, this concept of executing the program under test means each run is now always the same.
For instance, for in-memory fuzzers like libFuzzer an execution is a call to an harness function, for hypervisor-based fuzzers like [kAFL](https://github.com/IntelLabs/kAFL) instead an entire operating system is started from a snapshot for each run.

In our model, an Executor is the entity that defines not only how to execute the target, but all the volatile operations that are related to just a single run of the target.

So the Executor is for instance responsible to inform the program about the input that the fuzzer wants to use in the run, writing to a memory location for instance or passing it as a parameter to the harness function.

In our model, it can also hold a set of Observers connected with each execution.

In Rust, we bind this concept to the [`Executor`](https://docs.rs/libafl/latest/libafl/executors/trait.Executor.html) trait. A structure implementing this trait must implement [`HasObservers`](https://docs.rs/libafl/latest/libafl/executors/trait.HasObservers.html) too if wants to hold a set of Observers.

By default, we implement some commonly used Executors such as [`InProcessExecutor`](https://docs.rs/libafl/latest/libafl/executors/inprocess/type.InProcessExecutor.html) in which the target is a harness function providing in-process crash detection. Another Executor is the [`ForkserverExecutor`](https://docs.rs/libafl/latest/libafl/executors/forkserver/struct.ForkserverExecutor.html) that implements an AFL-like mechanism to spawn child processes to fuzz.

## InProcessExecutor

Let's begin with the base case; `InProcessExecutor`.
This executor executes the harness program (function) inside the fuzzer process.

When you want to execute the harness as fast as possible, you will most probably want to use this `InprocessExecutor`.

One thing to note here is, when your harness is likely to have heap corruption bugs, you want to use another allocator so that corrupted heap does not affect the fuzzer itself. (For example, we adopt MiMalloc in some of our fuzzers.). Alternatively you can compile your harness with address sanitizer to make sure you can catch these heap bugs.

## ForkserverExecutor

Next, we'll take a look at the `ForkserverExecutor`. In this case, it is `afl-cc` (from AFL/AFLplusplus) that compiles the harness code, and therefore, we can't use `EDGES_MAP` anymore. Fortunately we have [_a way_](https://github.com/AFLplusplus/AFLplusplus/blob/2e15661f184c77ac1fbb6f868c894e946cbb7f17/instrumentation/afl-compiler-rt.o.c#L270) to tell the forkserver which map to record the coverage in.

As you can see from the forkserver example,

```rust,ignore
//Coverage map shared between observer and executor
let mut shmem = StdShMemProvider::new().unwrap().new_shmem(MAP_SIZE).unwrap();
//let the forkserver know the shmid
unsafe {
    shmem.write_to_env("__AFL_SHM_ID").unwrap();
}
let mut shmem_buf = shmem.as_slice_mut();
```

Here we make a shared memory region; `shmem`, and write this to environmental variable `__AFL_SHM_ID`. Then the instrumented binary, or the forkserver, finds this shared memory region (from the aforementioned env var) to record its coverage. On your fuzzer side, you can pass this shmem map to your `Observer` to obtain coverage feedbacks combined with any `Feedback`.

Another feature of the `ForkserverExecutor` to mention is the shared memory testcases. In normal cases, the mutated input is passed between the forkserver and the instrumented binary via `.cur_input` file. You can improve your forkserver fuzzer's performance by passing the input with shared memory.

If the target is configured to use shared memory testcases, the `ForkserverExecutor` will notice this during the handshake and will automatically set up things accordingly.
See AFL++'s [_documentation_](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md#5-shared-memory-fuzzing) or the fuzzer example in `forkserver_simple/src/program.c` for reference.

## InprocessForkExecutor

Finally, we'll talk about the `InProcessForkExecutor`.
`InProcessForkExecutor` has only one difference from `InprocessExecutor`; It forks before running the harness and that's it.

But why do we want to do so? Well, under some circumstances, you may find your harness pretty unstable or your harness wreaks havoc on the global states. In this case, you want to fork it before executing the harness runs in the child process so that it doesn't break things.

However, we have to take care of the shared memory, it's the child process that runs the harness code and writes the coverage to the map.

We have to make the map shared between the parent process and the child process, so we'll use shared memory again. You should compile your harness with `pointer_maps` (for `libafl_targets`) features enabled, this way, we can have a pointer; `EDGES_MAP_PTR` that can point to any coverage map.

On your fuzzer side, you can allocate a shared memory region and make the `EDGES_MAP_PTR` point to your shared memory.

```rust,ignore
let mut shmem;
unsafe{
    shmem = StdShMemProvider::new().unwrap().new_shmem(EDGES_MAP_DEFAULT_SIZE).unwrap();
}
let shmem_buf = shmem.as_slice_mut();
unsafe{
    EDGES_PTR = shmem_buf.as_ptr();
}
```

Again, you can pass this shmem map to your `Observer` and `Feedback` to obtain coverage feedbacks.

Additionaly to allow the fuzzer to know when the child has crashed, the program should abort instead of unwinding upon a panic.
Without it, no crashes are saved by the fuzzer.

Cargo.toml:

```toml
[profile.dev]
panic = "abort"

[profile.release]
panic = "abort"
```
