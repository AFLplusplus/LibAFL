#!/bin/sh

mkdir -p ./crashes

cargo build --example libfuzzer_libmozjpeg --release || exit 1
cp ../../target/release/examples/libfuzzer_libmozjpeg ./.libfuzzer_test.elf

# The broker
RUST_BACKTRACE=full taskset 0 ./.libfuzzer_test.elf &
# Give the broker time to spawn
sleep 2
echo "Spawning client"
RUST_BACKTRACE=full ./.libfuzzer_test.elf 2>/dev/null

killall .libfuzzer_test.elf
rm -rf ./.libfuzzer_test.elf
