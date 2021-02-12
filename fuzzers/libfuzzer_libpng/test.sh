#!/bin/sh

cargo build --release || exit 1
cp ../../target/release/libfuzzer ./.libfuzzer_test.elf

RUST_BACKTRACE=full ./.libfuzzer_test.elf

rm -rf ./.libfuzzer_test.elf
