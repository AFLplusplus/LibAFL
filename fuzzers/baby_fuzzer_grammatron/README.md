# Baby fuzzer

This is a minimalistic example about how to create a libafl based fuzzer.

It runs on a single core until a crash occurs and then exits.

The tested program is a simple Rust function without any instrumentation.
For real fuzzing, you will want to add some sort to add coverage or other feedback.