# Configurations

Configurations for individual fuzzer nodes are relevant for multi node fuzzing.
The chapter describes how to run nodes with different configurations
in one fuzzing cluster.
This allows, for example, a node compiled with ASan, to know that it needs to rerun new testcases for a node without ASan, while the same binary/configuration does not.

Fuzzers with the same configuration can exchange Observers for new testcases and reuse them without rerunning the input.
A different configuration indicates, that only the raw input can be exchanged, it must be rerun on the other node to capture relevant observations.
