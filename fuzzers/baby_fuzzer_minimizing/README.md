# Baby fuzzer

This is a minimalistic example about how to create a libafl based fuzzer which leverages minimisation.

The fuzzer steps until a crash occurs, minimising each corpus entry as it is discovered. Then, once a
solution is found, it attempts to minimise that as well.

The tested program is a simple Rust function without any instrumentation.
For real fuzzing, you will want to add some sort to add coverage or other feedback.