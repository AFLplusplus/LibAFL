# Baby fuzzer with RedQueen-based CmpLog

This is a minimalistic example demonstrating the use of the `cmplog_extended_instrumentation` feature of LibAFL, all in-process. For a more production-quality reference, see the `fuzzbench_forkserver_cmplog` fuzzer.

The tested program is a simple function with comparisons to 16, 32,
and 64 bit magic values, which are difficult/impossible for a simple
bitflipping fuzzer to solve.

Build and run with `just run`, or `just test`, which is a CI target
that checks that the run triggers a crash within a couple of minutes.
