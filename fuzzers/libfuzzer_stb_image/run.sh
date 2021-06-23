#!/bin/sh

rm -rf ./crashes
rm -rf ./libfuzzer_stb_image

# Build the fuzzer
cargo build --release || exit 1

cp ./target/release/libfuzzer_stb_image .

# The broker
./libfuzzer_stb_image > broker_log 2>&1 &
# Give the broker time to spawn
sleep 2
echo "Spawning client"
# The 1st fuzzer client, pin to cpu 0x1
timeout 3s ./libfuzzer_stb_image 2>/dev/null

killall libfuzzer_stb_image
rm -rf ./libfuzzer_stb_image
rm -rf ./broker_log
exit 0