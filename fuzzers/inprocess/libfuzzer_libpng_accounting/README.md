# Libfuzzer for libpng, with launcher

This folder contains an example fuzzer for libpng, using LLMP for fast multi-process fuzzing and crash detection.
To show off crash detection, we added a `ud2` instruction to the harness, edit harness.cc if you want a non-crashing example.
It has been tested on Linux.

In contrast to the normal libfuzzer libpng example, this uses the `launcher` feature, that automatically spawns `n` child processes, and binds them to a free core.

## Build

To build this example, run

```bash
cargo build --release
```

This will build the library with the fuzzer (src/lib.rs) with the libfuzzer compatibility layer and the SanitizerCoverage runtime functions for coverage feedback.
In addition, it will also build two C and C++ compiler wrappers (bin/libafl_c(libafl_c/xx).rs) that you must use to compile the target.

Then download libpng, and unpack the archive:
```bash
wget https://github.com/glennrp/libpng/archive/refs/tags/v1.6.37.tar.gz
tar -xvf v1.6.37.tar.gz
```

Now compile libpng, using the libafl_cc compiler wrapper:

```bash
cd libpng-1.6.37
./configure
make CC=../target/release/libafl_cc CXX=../target/release/libafl_cxx -j `nproc`
```

You can find the static lib at `libpng-1.6.37/.libs/libpng16.a`.

Now, we have to build the libfuzzer harness and link all together to create our fuzzer binary.

```
cd ..
./target/release/libafl_cxx ./harness.cc libpng-1.6.37/.libs/libpng16.a -I libpng-1.6.37/ -o fuzzer_libpng -lz -lm
```

Afterwards, the fuzzer will be ready to run.

## Run

Just run once, the launcher feature should do the rest.