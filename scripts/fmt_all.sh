#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

echo "Welcome to the happy fmt script. :)"
echo "[*] Running fmt for the main crates"
cargo fmt

cd fuzzers

for fuzzer in *;
do
    cd $fuzzer
    echo "[*] Running fmt for $fuzzer"
    cargo fmt --all
    cd ..
done
