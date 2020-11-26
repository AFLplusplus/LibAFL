#!/bin/sh

cargo build --release
make -C runtime

./compiler test/test.c -o test_fuzz.elf

RUST_BACKTRACE=1 ./test_fuzz.elf

rm ./test_fuzz.elf
