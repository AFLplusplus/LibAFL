#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

echo "Welcome to the happy fmt script. :)"
echo "[*] Running fmt for the main crates"
cargo fmt

echo "[*] Formatting C(pp) files"
clang-format-13 -i --style=file $(find -E . -regex '.*\.(cpp|hpp|cc|cxx|c|h)' | grep -ve 'target' | grep -ve 'libpng-1.6.37')

fuzzers=$(find ./fuzzers -maxdepth 1 -type d)
backtrace_fuzzers=$(find ./fuzzers/backtrace_baby_fuzzers -maxdepth 1 -type d)

for fuzzer in $(echo $fuzzers $backtrace_fuzzers);
do
    pushd $fuzzer
    echo "[*] Running fmt for $fuzzer"
    cargo fmt --all
    popd
done
