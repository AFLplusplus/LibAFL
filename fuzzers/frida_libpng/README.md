# Libfuzzer for libpng

This folder contains an example fuzzer for libpng, using LLMP for fast multi-process fuzzing and crash detection.
To show off crash detection, we added a ud2 instruction to the harness, edit harness.cc if you want a non-crashing example.
It has been tested on Linux.

## Build

To build this example, run `cargo build --release` in this folder.
This will call (the build.rs)[./build.rs], which in turn downloads a libpng archive from the web.
Then, it will link (the fuzzer)[./src/fuzzer.rs] against (the C++ harness)[./harness.cc] and the instrumented `libpng`.
Afterwards, the fuzzer will be ready to run, from `target/frida_libpng`.

### Build For Android
When building for android using a cross-compiler, make sure you have a _standalone toolchain_, and then add the following:
1. In the ~/.cargo/config file add a target with the correct cross-compiler toolchain name (in this case aarch64-linux-android, but names may vary)
`[target.aarch64-linux-android]`
`linker="aarch64-linux-android-clang"`
2. add path to installed toolchain to PATH env variable.
3. define CLANG_PATH and add target to the build command line:
`CLANG_PATH=<path to installed toolchain>/bin/aarch64-linux-android-clang cargo -v build --release --target=aarch64-linux-android`

## Run

This example uses in-process-fuzzing, using the `launcher` feature, in combination with a Restarting Event Manager.
This means running --cores each client will start itself again to listen for crashes and timeouts.
By restarting the actual fuzzer, it can recover from these exit conditions.

After building the libpng-harness, too, you can run `find . -name libpng-harness.so` to find the location of your harness, then run
`./target/release/frida_libpng ./libpng-harness.so LLVMFuzzerTestOneInput ./libpng-harness.so --cores=0`