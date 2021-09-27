# Klo-based Fuzzer with Push Harness

*Linux only*

This is a minimalistic example create a fuzzer for Linux that pulls data out of LibAFL, instead of being called by it repeatedly.
Use this only if there is absolutely no way to have a traditional harness function that gets called, but the target *needs* to call the fuzzer, instead.
This technique comes at some runtime overhead, and you should very likely not need it for everyday fuzzing.