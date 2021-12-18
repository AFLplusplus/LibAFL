#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

cd fuzzers

for fuzzer in *;
do
    cd $fuzzer
    # Clippy checks
    if [ "$1" != "--no-fmt" ]; then
        
        echo "[*] Checking fmt for $fuzzer"
        cargo fmt --all -- --check || exit 1
        echo "[*] Running clippy for $fuzzer"
        cargo clippy || exit 1
    else
        echo "[+] Skipping fmt and clippy for $fuzzer (--no-fmt specified)"
    fi

    if [ -e ./Makefile ]; then
        echo "[*] Testing $fuzzer"
        make short_test || exit 1
	    echo "[+] Done testing $fuzzer"
    else
        echo "[*] Building $fuzzer"
        cargo build || exit 1
        echo "[+] Done building $fuzzer"
    fi

    # Save disk space
    cargo clean
    cd ..
    echo ""
done
