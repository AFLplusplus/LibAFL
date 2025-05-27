# Simple Forkserver Fuzzer to Capture Stdout

This is a simple example fuzzer to showcase how to capture stdout(stderr) from `ForkserverExecutor`.

## Usage
You can build this example by `cargo build --release`.  
This downloads AFLplusplus/AFLplusplus and compiles the example harness program in src/program.c with afl-cc  

## Run
After you build it you can run  
`cp ./target/release/forkserver_capture_stdout .` to copy the fuzzer into this directory,  
and you can run  
`taskset -c 1 ./forkserver_capture_stdout ./target/release/program ./corpus/ -t 1000` to run the fuzzer.
`taskset` binds this process to a specific core to improve the throughput.  