#!/bin/sh

rm -rf ./crashes
rm -rf ./fuzzer_mozjpeg

cargo build --release || exit 1

if [ ! -d mozjpeg-4.0.3 ]; then
    wget https://github.com/mozilla/mozjpeg/archive/v4.0.3.tar.gz || exit 1
    tar -xzvf v4.0.3.tar.gz
fi

# Build .a file
if [ ! -e mozjpeg-4.0.3/libjpeg.a ]; then
    cd mozjpeg-4.0.3
    cmake . -DENABLE_SHARED=FALSE -DCMAKE_C_COMPILER="$(pwd)../target/release/libafl_cc" -DCMAKE_CXX_COMPILER="$(pwd)../target/release/libafl_cxx" -G "Unix Makefiles" || exit 1
    make -j `nproc` || exit 1
    cd ..
fi

# Compile the harness
./target/release/libafl_cxx ./harness.cc ./mozjpeg-4.0.3/*.a -I ./mozjpeg-4.0.3/ -o fuzzer_mozjpeg || exit 1
# The broker
./fuzzer_mozjpeg > broker_log 2>&1 &
# Give the broker time to spawn
sleep 2
echo "Spawning client"
# The 1st fuzzer client, pin to cpu 0x1
timeout 3s ./fuzzer_mozjpeg 2>/dev/null

killall fuzzer_mozjpeg
rm -rf ./fuzzer_mozjpeg
rm -rf ./broker_log
exit 0
