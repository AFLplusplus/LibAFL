# Simple Rust-only Forkserver Fuzzer

A minimal forkserver fuzzer with a pure Rust target binary — no C toolchain required.

## Usage
You can build this example by `cargo build --release`.
This produces two binaries: `target/release/forkserver_simple_rs` (fuzzer) and `target/release/target` (harness).

## Run
After you build it you can run
`./target/release/forkserver_simple_rs ./corpus` to run the fuzzer.
Use `-p` for persistent mode (`./target/release/forkserver_simple_rs ./corpus -p`).
