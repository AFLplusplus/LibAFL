#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/.."

# TODO: This should be rewritten in rust, a Makefile, or some platform-independent language

# restore timestamp of file and dir by git history
echo -e "[*] restore timestamp of file and dir by git history"
rev=HEAD
for f in $(git ls-tree -r -t --full-name --name-only "$rev") ; do
     touch -t $(git log --pretty=format:%cd --date=format:%Y%m%d%H%M.%S -1 "$rev" -- "$f") "$f"; 
done

# list fuzzers by time
fuzzers=$(ls -dt fuzzers/*/)
backtrace_fuzzers=$(find ./fuzzers/backtrace_baby_fuzzers -maxdepth 1 -type d)

libafl=$(pwd)

echo -e "[*] test starts from latest modified fuzzer,here is the order:\n${fuzzers}"
echo "[*] start testing"
git submodule init && git submodule update
for fuzzer in $(echo $fuzzers $backtrace_fuzzers);
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

    if [ -e ./Makefile.toml ]; then
        echo "[*] Testing $fuzzer"
        cargo make test || exit 1
	    echo "[+] Done testing $fuzzer"
    else
        echo "[*] Building $fuzzer"
        cargo build || exit 1
        echo "[+] Done building $fuzzer"
    fi

    # Save disk space
    cargo clean
    cd $libafl
    echo ""
done
