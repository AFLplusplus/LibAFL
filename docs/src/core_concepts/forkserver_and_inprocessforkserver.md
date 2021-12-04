# ForkserverExecutor and InprocessForkExecutor

## Introduction
We have `ForkserverExecutor` and `InprocessForkExecutor` in libafl crate.  
On this page, we'll quickly explain how they work and see how they compare to normal `InProcessExecutor`

## InprocessExecutor
Let's begin with the base case; `InProcessExecutor`.
This executor uses [_SanitizerCoverage_](https://clang.llvm.org/docs/SanitizerCoverage.html) as its backend, as you can find the related code in `libafl_targets/src/sancov_pcguards`. Here we allocate a map called `EDGES_MAP` and then our compiler wrapper compiles the harness to write the coverage into this map.  

## ForkserverExecutor
Next, we'll look at the `ForkserverExecutor`. In this case, it is `afl-cc` (from AFLplusplus/AFLplusplus) that compiles the harness code, and therefore, we can't use `EDGES_MAP` anymore. Hopefully, we have [_a way_](https://github.com/AFLplusplus/AFLplusplus/blob/2e15661f184c77ac1fbb6f868c894e946cbb7f17/instrumentation/afl-compiler-rt.o.c#L270) to tell the forkserver which map to record the coverage.
As you can see from the forkserver example,
```rust,ignore
//Coverage map shared between observer and executor
let mut shmem = StdShMemProvider::new().unwrap().new_map(MAP_SIZE).unwrap();
//let the forkserver know the shmid
shmem.write_to_env("__AFL_SHM_ID").unwrap();
let mut shmem_map = shmem.map_mut();
```
Here we make a shared memory region; `shmem`, and write this to environmental variable `__AFL_SHM_ID`. Then the instrumented binary, or the forkserver, finds this shared memory region (from the aforementioned env var) to record its coverage. On your fuzzer side, you can pass this shmem map to your `Observer` to obtain coverage feedbacks combined with any `Feedback`.

Another feature of the `ForkserverExecutor` to mention is the shared memory testcases. In normal cases, the mutated input is passed between the forkserver and the instrumented binary via `.cur_input` file. You can improve your forkserver fuzzer's performance by passing the input with shared memory.
See AFL++'s [_documentation_](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md) or the fuzzer example in `forkserver_simple/src/program.c` for reference.  
It is very simple, when you call `ForkserverExecutor::new()` with `use_shmem_testcase` true, the `ForkserverExecutor` sets things up and your harness can just fetch the input from `__AFL_FUZZ_TESTCASE_BUF`

## InprocessForkExecutor
Finally, we'll talk about the `InProcessForkExecutor`.
`InProcessForkExecutor` has only one difference from `InprocessExecutor`; It forks before running the harness and that's it.  
But why do we want to do so? well, under some circumstances, you may find your harness pretty unstable or your harness wreaks havoc on the global states. In this case, you want to fork it before executing the harness runs in the child process so that it doesn't break things.  
However, we have to take care of the shared memory, it's the child process that runs the harness code and writes the coverage to the map.  
We have to make the map shared between the parent process and the child process, so we'll use shared memory again. You should compile your harness with `pointer_maps` (for `libafl_targes`) features enabled, this way, we can have a pointer; `EDGES_MAP_PTR` that can point to any coverage map.
On your fuzzer side, you can allocate a shared memory region and make the `EDGES_MAP_PTR` point to your shared memory.
```rust,ignore
let mut shmem;
unsafe{
    shmem = StdShMemProvider::new().unwrap().new_map(MAX_EDGES_NUM).unwrap();
}
let shmem_map = shmem.map_mut();
unsafe{
    EDGES_PTR = shmem_map.as_ptr();
}
```
Again, you can pass this shmem map to your `Observer` and `Feedback` to obtain coverage feedbacks.
