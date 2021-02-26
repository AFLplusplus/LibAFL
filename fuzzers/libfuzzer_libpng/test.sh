#!/bin/sh

mkdir -p ./crashes

cargo build --release || exit 1
cp ./target/release/libfuzzer_libpng ./.libfuzzer_test.elf

RUST_BACKTRACE=full ./.libfuzzer_test.elf
