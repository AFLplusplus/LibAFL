# Observer

An Observer, or Observation Channel, is an entity that provides an information observed during the execution of the program under test to the fuzzer.

The information contained in the Observer is not preserved cross executions.

As an example, the coverage shared map filled during the execution to report the executed edges used by fuzzers such as AFL and HoggFuzz can be considered an Observation Channel.
This information is not preserved accros runs and it is an observation of a dynamic property of the program.

