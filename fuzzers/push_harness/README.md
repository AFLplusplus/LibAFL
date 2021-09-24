# Klo-based Iterator fuzzer

This is a minimalistic example create a fuzzer for Linux that pulls data out of LibAFL, instead of being called by it repaetedly.
Use this only if there is absolutely no way to have a traditional harness function that gets called, but the target *needs* to call the fuzzer, instead.
This will rarely be the case.

