# Baby fuzzer with Custom Executor

This is a minimalistic example about how to create a LibAFL-based fuzzer.

In contrast to the normal baby fuzzer, this uses a (very simple) custom executor.

The custom executor won't catch any timeouts or actual errors (i.e., memory corruptions, etc.) in the target.

The tested program is a simple Rust function without any instrumentation.
For real fuzzing, you will want to add some sort to add coverage or other feedback.

You can run this example using `cargo run`, and you can enable the TUI feature by running `cargo run --features tui`.
