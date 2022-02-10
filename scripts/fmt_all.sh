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
    if [[ -d $fuzzer ]]
    then
        cd $fuzzer
        echo "[*] Running fmt for $fuzzer"
        cargo fmt --all
        cd ..
    fi
done

cd backtrace_baby_fuzzers
for fuzzer in *;
do
    if [[ -d $fuzzer ]]
    then
        cd $fuzzer
        echo "[*] Running fmt for backtrace_baby_fuzzers/$fuzzer"
        cargo fmt --all
        cd ..
    fi
done
cd ..