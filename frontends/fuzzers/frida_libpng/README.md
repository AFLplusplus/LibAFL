# Libfuzzer for libpng

This folder contains an example fuzzer for libpng, using LLMP for fast multi-process fuzzing and crash detection.
To show off crash detection, we added a ud2 instruction to the harness, edit harness.cc if you want a non-crashing example.
It has been tested on Linux.

## Build

To build this example, run `cargo build --release` in this folder.
This will call (the build.rs)[./build.rs], which in turn downloads a libpng archive from the web.
Then, it will link (the fuzzer)[./src/fuzzer.rs] against (the C++ harness)[./harness.cc] and the instrumented `libpng`.
Afterwards, the fuzzer will be ready to run, from `target/frida_libpng`.  
On unix platforms, you'll need [libc++](https://libcxx.llvm.org/) to build it.

Alternatively you can run `cargo make run` and this command will automatically build and run the fuzzer

### Build For Android
When building for android using a cross-compiler, make sure you have a [_standalone toolchain_](https://developer.android.com/ndk/guides/standalone_toolchain), and then add the following:
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

After building the libpng-harness, you can run `find . -name libpng-harness.so` to find the location of your harness, then run
`./frida_fuzzer -F LLVMFuzzerTestOneInput -H ./libpng-harness.so -l ./libpng-harness.so`

## Windows
You can also fuzz libpng-1.6.37 on windows with frida mode

### To build it with visual studio
1. Install clang for windows (make sure you add LLVM to the system path!) 
[https://github.com/llvm/llvm-project/releases/tag/llvmorg-12.0.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-12.0.1)
2. Download libpng-1.6.37[https://deac-fra.dl.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz] and zlib [https://zlib.net/fossils/zlib-1.2.11.tar.gz] into this directory, and rename `zlib-1.2.11` directory to `zlib`.

3. Build libpng1.6.37 
   - Open libpng-1.6.37/projects/vstudio/vstudio.sln 
   - Open Build->Configuration Manager 
      - select Release for Active solution configuration and 
      - select <New>->x64 for Active solution platform (Copy settings from Win32) 
   - Then for libpng, pngstest, pngtest, pngunknown, pngvalid, zlib in Solution Explorer, choose General -> Configuration Type -> Static library(.lib) 
      - C/C++ -> Treat Warnings As Errors -> No
      - C/C++ -> Code Generation -> Runtime Library -> Multi-threaded (/MT)
   - Finally, you can build libpng-1.6.37
4. Compile the harness
Fire up a powershell at this directory.
```
cp .\libpng-1.6.37\projects\vstudio\x64\Release\libpng16.lib .
cp .\libpng-1.6.37\projects\vstudio\x64\Release\zlib.lib .
cp .\target\release\frida_libpng.exe .
clang++ -O3 -c -I.\libpng-1.6.37 .\harness.cc -o .\harness.o
clang++ -L.\zlib.dll .\harness.o .\libpng16.lib -lzlib -shared -o .\libpng-harness.dll
```
5. Run the fuzzer
```
./frida_fuzzer.exe ./libpng-harness.dll LLVMFuzzerTestOneInput ./libpng-harness.dll
```

