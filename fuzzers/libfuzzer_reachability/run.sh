#!/bin/sh

rm -rf ./crashes
rm -rf ./fuzzer_libpng

cargo build --release || exit 1

if [ ! -d libpng-1.6.37 ]; then
    wget https://deac-fra.dl.sourceforge.net/project/libpng/libpng16/1.6.37/libpng-1.6.37.tar.xz || exit 1
    tar -xvf libpng-1.6.37.tar.xz
fi

echo "Patching libpng"
patch libpng-1.6.37/png.c diff.patch || exit 1

# Build libpng.a
if [ ! -e libpng-1.6.37/.libs/libpng16.a ]; then
    cd libpng-1.6.37
    ./configure || exit 1
    make CC="$(pwd)/../target/release/libafl_cc" CXX="$(pwd)/../target/release/libafl_cxx" -j $(nproc || echo 6) || exit 1
    cd ..
fi

# Compile the harness
./target/release/libafl_cxx ./harness.cc libpng-1.6.37/.libs/libpng16.a -I libpng-1.6.37/ -o fuzzer_libpng -lz -lm || exit 1

# The broker
./fuzzer_libpng > broker_log 2>&1 &
# Give the broker time to spawn
sleep 2
echo "Spawning client"
# The 1st fuzzer client, pin to cpu 0x1
timeout 3s ./fuzzer_libpng 2>/dev/null

killall fuzzer_libpng
rm -rf ./fuzzer_libpng
rm -rf ./broker_log
exit 0