# Libfuzzer for libmozjpeg

This folder contains an example fuzzer for libmozjpeg, using LLMP for fast multi-process fuzzing and crash detection.
Alongside the traditional edge coverage, this example shows how to use a value-profile like feedback to bypass CMPs and an allocations size maximization feedback to spot patological inputs in terms of memory usage.
It has been tested on Linux.

## Build

To build this example, run `cargo build --release`.
This will build the library with the fuzzer (src/lib.rs) with the libfuzzer compatibility layer. the SanitizerCoverage runtime functions for edges and value-profile feedbacks and the `hook_allocs.c` C file that hooks the allocator to report the size to the fuzzer.
In addition, it will build also two C and C++ compiler wrappers (bin/c(c/xx).rs) that you must use to compile the target.

Then download the mozjpeg source tarball from  and unpack the archive:
```bash
wget https://github.com/mozilla/mozjpeg/archive/v4.0.3.tar.gz
tar -xzvf v4.0.3.tar.gz
```

Now compile it with:

```
cd mozjpeg-4.0.3
cmake --disable-shared . -DCMAKE_C_COMPILER="$(pwd)/../target/release/libafl_cc" -DCMAKE_CXX_COMPILER="$(pwd)/../target/release/libafl_cxx" -G "Unix Makefiles"
make -j `nproc`
cd ..
```

Now, we have to build the libfuzzer harness and link all together to create our fuzzer binary.

```
./target/debug/cxx ./harness.cc ./mozjpeg-4.0.3/*.a -I ./mozjpeg-4.0.3/ -o fuzzer_mozjpeg
```

Afterward, the fuzzer will be ready to run by simply executing `./fuzzer_mozjpeg`.
Note that, unless you use the `launcher`, you will have to run the binary multiple times to actually start the fuzz process, see `Run` in the following.
This allows you to run multiple different builds of the same fuzzer alongside, for example, with and without ASAN (`-fsanitize=address`) or with different mutators.

## Run

The first time you run the binary, the broker will open a tcp port (currently on port `1337`), waiting for fuzzer clients to connect. This port is local and only used for the initial handshake. All further communication happens via shared map, to be independent of the kernel.

Each following execution will run a fuzzer client.
As this example uses in-process fuzzing, we added a Restarting Event Manager (`setup_restarting_mgr`).
This means each client will start itself again to listen for crashes and timeouts.
By restarting the actual fuzzer, it can recover from these exit conditions.

In any real-world scenario, you should use `taskset` to pin each client to an empty CPU core, the lib does not pick an empty core automatically, unless you use the `launcher`.
