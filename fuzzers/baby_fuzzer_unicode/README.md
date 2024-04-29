# Baby fuzzer: unicode

This is a minimalistic example about how to create a libafl based fuzzer.

It runs on a single core until a crash occurs and then exits.

The tested program is a simple Rust function without any instrumentation.
For real fuzzing, you will want to add some sort to add coverage or other feedback.

You can run this example using `cargo run`, and you can enable the TUI feature by running `cargo run --features tui`.

## Unicode

This fuzzer uses mutators which preserve unicode properties. For programs which have string-heavy inputs, you may
consider using the same strategy.