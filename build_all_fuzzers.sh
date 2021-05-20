#!/bin/sh

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

cd fuzzers

for fuzzer in *;
do
    echo "[+] Checking fmt, and building $fuzzer"
    cd $fuzzer \
        && cargo fmt --all -- --check \
        # && ../../clippy.sh --no-clean \ # No clippy for example fuzzers
        && cargo build \
        && cd .. \
    || exit 1
done
