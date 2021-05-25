# Simple Forkserver Fuzzer

This is a simple fuzzer to test the ForkserverExecutor.
You can test it with the following procedures.
1. `cargo build --release`
2. `cp ./target/release/forkserver_simple .`
3. `taskset -c 1 ./forkserver_simple`