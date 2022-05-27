#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

echo "Welcome to the happy clean script. :)"
echo "[*] Running clean for the main crates"
cargo clean

fuzzers=$(find ./fuzzers -maxdepth 1 -type d)
backtrace_fuzzers=$(find ./fuzzers/backtrace_baby_fuzzers -maxdepth 1 -type d)

# shellcheck disable=SC2116
for fuzzer in $(echo "$fuzzers" "$backtrace_fuzzers");
do
    pushd "$fuzzer" || exit 1
    echo "[*] Running clean for $fuzzer"
    cargo clean
    popd || exit 1
done
