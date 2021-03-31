# Executor

In different fuzzers, the concept of executing the program under test each run is now always the same.
For instance, for in-memory fuzzers like libFuzzer an execution is a call to an harness function, for hypervisor-based fuzzers like [kAFL](https://github.com/IntelLabs/kAFL) instead an entire operating system is started from a snapshot each run.

In our model, an Executor is the entity that defines not only how to execute the target, but all the volatile operations that are related to just a single run of the target.

So the Executor is for instance reponsible to inform the program about the input that the fuzzer wants to use in the run, writing to a memory location for instance or passing it as a parameter to the harness function.

It also holds a set of Observers, as thay are related to just a single run of the target.
