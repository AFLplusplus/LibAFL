# DeExit

This util helps you, if your target calls `exit` during a fuzz run.
A simple wrapper that can be inserted into a program to turn `exit` calls to `abort`, which LibAFL will be able to catch.
If you are on MacOS, use the env variables `DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="path/to/target/release/libdeexit.dylib" tool`
On Linux, use `LD_PRELOAD="path/to/target/release/libdeexit.so" tool`.
