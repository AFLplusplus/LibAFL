#!/bin/sh

cargo build --release
make -C runtime

./compiler test/test.c -o test_fuzz

./test_fuzz

rm ./test_fuzz
