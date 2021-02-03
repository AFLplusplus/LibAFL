
# LibAFL, the fuzzer library.


## Example usages

We collect example fuzzers in `./examples`.
The best-tested fuzzer is `./fuzzers/libfuzzer_libpng`, a clone of libfuzzer using libafl for a libpng harness.

## How to perf:

```
perf record -e task-clock ./PROGRAM

perf report --stdio --dsos=PROGRAM

rm perf.data
```
