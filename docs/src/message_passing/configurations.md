# Configurations

Configurations for individual fuzzer nodes are relevant for multi node fuzzing.
The chapter describes how to run nodes with different configurations
in one fuzzing cluster.
This allows, for example, a node compiled with ASAN, to know that it needs to rerun new testcases for a node without ASAN, while the same binary/configuration does not.

> ## Under Construction!
> This section is under construction.
> Please check back later (or open a PR)
