# Baby fuzzer (swap differential)

This is a minimalistic example about how to create a libafl-based differential fuzzer which swaps out the AFL map during
execution so that both maps may be measured.

It runs on a single core until an input is discovered which both inputs accept.

The tested programs are provided in `first.c` and `second.c`.

You may execute this fuzzer with `cargo make run`. If you prefer to do so manually, you may also simply use
`cargo build --release --bin libafl_cc` followed by `cargo run --release --bin fuzzer_sd`