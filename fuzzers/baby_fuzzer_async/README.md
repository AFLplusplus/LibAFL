# Baby fuzzer

This is a minimalistic example about how to create a libafl based fuzzer with asynchronous executors.

The tested program is a simple Rust function without any instrumentation.
For real fuzzing, you will want to add some sort to add coverage or other feedback.
For asynchronous fuzzing, you will likely wish to send inputs over a network connection or pipe, not just sleep.