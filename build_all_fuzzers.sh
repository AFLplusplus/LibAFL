#!/bin/sh

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

cd fuzzers

for fuzzer in *;
do
    echo "[+] Building $fuzzer"
    cd $fuzzer && cargo build && cd .. || exit 1
done