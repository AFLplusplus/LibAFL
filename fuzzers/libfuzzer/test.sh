#!/bin/sh

cargo build || exit 1
make -C runtime || exit 1

rm -f test_fuzz.elf test_fuzz.o
./compiler -flto=thin -c test/test.c -o test_fuzz.o || exit 1
./compiler -flto=thin test_fuzz.o -o test_fuzz.elf || exit 1

RUST_BACKTRACE=1 ./test_fuzz.elf &

test "$!" -gt 0 && {

  usleep 250
  RUST_BACKTRACE=1 ./test_fuzz.elf -x a -x b -T5 in1 in2 &

}

sleep 10
killall test_fuzz.elf

