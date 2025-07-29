# Simple Forkserver Fuzzer

This is a simple example fuzzer to fuzz a executable instrumented by afl-cc.
## Usage
You can build this example by `cargo build --release`.  
This downloads AFLplusplus/AFLplusplus and compiles the example harness program in src/program.c with afl-cc  

## Run
After you build it you can run  
`cp ./target/release/forkserver_simple .` to copy the fuzzer into this directory,  
and you can run  
`taskset -c 1 ./target/release/forkserver_simple -g src/grammar.py -t 1000 -- ./target/release/program` to run the fuzzer.
`taskset` binds this process to a specific core to improve the throughput.  