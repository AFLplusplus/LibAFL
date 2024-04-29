#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.." || exit 1

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

echo "Welcome to the happy fmt script. :)"
echo "[*] Running fmt for the main crates"
cargo +nightly fmt

echo "[*] Formatting C(pp) files"
# shellcheck disable=SC2046
clang-format-18 -i --style=file $(find . -type f \( -name '*.cpp' -o -iname '*.hpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.cc' -o -name '*.c' -o -name '*.h' \) | grep -v '/target/' | grep -v 'libpng-1\.6\.37' | grep -v 'stb_image\.h' | grep -v 'dlmalloc\.c')

fuzzers=$(find ./fuzzers -maxdepth 1 -type d)
backtrace_fuzzers=$(find ./fuzzers/backtrace_baby_fuzzers -maxdepth 1 -type d)

# shellcheck disable=SC2116
for fuzzer in $(echo "$fuzzers" "$backtrace_fuzzers");
do
    pushd "$fuzzer" || exit 1
    echo "[*] Running fmt for $fuzzer"
    cargo +nightly fmt --all
    popd || exit 1
done

echo "[*] Formatting libafl_libfuzzer_runtime"
pushd "libafl_libfuzzer/libafl_libfuzzer_runtime" || exit 1
cargo +nightly fmt --all
popd || exit 1

echo "[*] Done :)"
