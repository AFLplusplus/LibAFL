# Crates

LibAFL is composed by different crates.
Each one has its self-contained purpose, and the user may not need to use all of them in its project.

Following the naming convention of the folders in the project's root, they are:

- libafl, the main crate that contains all the components needed to build a fuzzer
- libafl_derive, a proc-macro crate paired with the libafl crate
- libafl_targets, a crate that expose, under feature flags, pieces of code to interact with targets
- libafl_cc, a library that provide some utils to wrap compilers and create source level fuzzers.


