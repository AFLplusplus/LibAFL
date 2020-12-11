#!/bin/sh

cargo build --release
make -C runtime

./compiler -flto=thin -c test/test.c -o test_fuzz.o
./compiler -flto=thin -fuse-ld=lld test_fuzz.o -o test_fuzz.elf

RUST_BACKTRACE=1 ./test_fuzz.elf

#rm ./test_fuzz.elf
