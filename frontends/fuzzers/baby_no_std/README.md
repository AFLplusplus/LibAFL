# Baby `no_std`

This is a minimalistic example how to create a libafl based fuzzer that works on `no_std` environments like TEEs, Kernels or on barew metal.

It runs on a single core until a crash occurs and then calls the panic handler.

The tested program is a simple Rust function without any instrumentation.
For real fuzzing, you will want to add some sort to add coverage or other feedback.