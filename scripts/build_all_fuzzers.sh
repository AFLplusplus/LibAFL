#!/bin/bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

cd fuzzers

for fuzzer in *;
do
    echo "[+] Checking fmt and building $fuzzer"
    cd $fuzzer \
        && cargo fmt --all -- --check \
        && cargo build \
        && cd .. \
    || exit 1
done
