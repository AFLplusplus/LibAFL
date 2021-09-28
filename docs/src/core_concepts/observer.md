# Observer

An Observer, or Observation Channel, is an entity that provides an information observed during the execution of the program under test to the fuzzer.

The information contained in the Observer is not preserved across executions.

As an example, the coverage shared map filled during the execution to report the executed edges used by fuzzers such as AFL and HonggFuzz can be considered an Observation Channel.
This information is not preserved across runs and it is an observation of a dynamic property of the program.

In terms of code, in the library this entity is described by the [`Observer`](https://docs.rs/libafl/0/libafl/observers/trait.Observer.html) trait.

In addition to holding the volatile data connected with the last execution of the target, the structures implementing this trait can define some execution hooks that are executed before and after each fuzz case. In this hooks, the observer can modify the fuzzer's state.
